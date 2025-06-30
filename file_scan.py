#!/usr/local/bin/python
# Copyright © 2019 The vt-py authors. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Uploads files to VirusTotal using vt-py."""

import asyncio
import itertools
import os
import sys
import vt

# Hardcoded API key and file path
API_KEY = open("apikey.txt",'r').read()  # Replace with your actual API key
UPLOAD_PATH = "./Files"  # Replace with the path to the file or directory
NUM_WORKERS = 3  # Number of concurrent upload workers

async def get_files_to_upload(queue, path):
    """Finds which files will be uploaded to VirusTotal."""
    if os.path.isfile(path):
        await queue.put(path)
        return 1

    n_files = 0
    with os.scandir(path) as it:
        for entry in it:
            if not entry.name.startswith(".") and entry.is_file():
                await queue.put(entry.path)
                n_files += 1
    return n_files

async def upload_hashes(queue, apikey):
    """Uploads selected files to VirusTotal."""
    return_values = []
    async with vt.Client(apikey) as client:
        while not queue.empty():
            file_path = await queue.get()
            with open(file_path, 'rb') as f:
                try:
                    analysis = await client.scan_file_async(file=f)
                    print(f"Uploaded: {file_path}")
                    return_values.append((analysis, file_path))
                except Exception as e:
                    print(f"Failed to upload {file_path}: {e}")
            queue.task_done()
    return return_values

async def process_analysis_results(apikey, analysis, file_path):
    """Processes and prints analysis results from VirusTotal."""
    async with vt.Client(apikey) as client:
        completed_analysis = await client.wait_for_analysis_completion(analysis)
        print(f"Results for {file_path}: {completed_analysis.stats}")
        print(f"Analysis ID: {completed_analysis.id}")

async def main():
    """Main function to upload and process files."""
    if not os.path.exists(UPLOAD_PATH):
        print(f"ERROR: File or directory {UPLOAD_PATH} not found.")
        sys.exit(1)

    queue = asyncio.Queue()
    n_files = await get_files_to_upload(queue, UPLOAD_PATH)

    worker_tasks = [
        asyncio.create_task(upload_hashes(queue, API_KEY))
        for _ in range(min(NUM_WORKERS, n_files))
    ]

    # Wait for uploads to complete
    analyses = itertools.chain.from_iterable(await asyncio.gather(*worker_tasks))
    await asyncio.gather(
        *[asyncio.create_task(process_analysis_results(API_KEY, a, f)) for a, f in analyses]
    )

if __name__ == "__main__":
    asyncio.run(main())
