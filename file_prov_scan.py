
import asyncio
import hashlib
import vt

# Hardcoded API key and file path
API_KEY = open("apikey.txt","r").read()  # Replace with your actual API key
FILE_PATH = "./Files/object.out"  # Replace with the actual file path


async def get_provenance_info(apikey, file_hash):
    async with vt.Client(apikey) as client:
        file_obj = await client.get_object_async(f'/files/{file_hash}')

    return (
        getattr(file_obj, 'monitor_info', None),
        getattr(file_obj, 'nsrl_info', None),
        getattr(file_obj, 'signature_info', None),
        getattr(file_obj, 'tags', []),
        getattr(file_obj, 'trusted_verdict', None),
    )


async def main():
    try:
        with open(FILE_PATH, "rb") as file:
            file_hash = hashlib.sha256(file.read()).hexdigest()

        monitor, nslr, signature, tags, trusted = await get_provenance_info(API_KEY, file_hash)

        if monitor:
            print(f'Present in monitor collections of {", ".join(monitor["organizations"])}')

        if nslr:
            print(f'Present in these products: {", ".join(nslr["products"])}')

        if signature:
            print(f'{"Inv" if "invalid-signature" in tags else "V"}alid signature.')
            print(f'Product: {signature["product"]}.')
            print(f'Signers: {signature["signers"]}')

        if trusted:
            print(f'Trusted file by {trusted["organization"]}')

    except vt.error.APIError as e:
        print(f'ERROR: {e}')
    except FileNotFoundError:
        print(f'ERROR: File not found at {FILE_PATH}')
    except Exception as e:
        print(f'ERROR: {e}')


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
    loop.close()
