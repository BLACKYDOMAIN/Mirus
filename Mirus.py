import streamlit as st

def read_api_key():
    """Reads the API key from apikey.txt in the current directory."""
    try:
        with open("apikey.txt", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        print("Error: apikey.txt not found in the current directory.")
        exit(1)

def Home():
    return

def Upload_Files():
    import os
    import subprocess

    uploaded_files = st.file_uploader(
        "Choose a CSV file", accept_multiple_files=True
    )
    for uploaded_file in uploaded_files:
        bytes_data = uploaded_file.read()
        st.write("filename:", uploaded_file.name)
        with open(os.path.join("Files",uploaded_file.name),"wb") as f:
           f.write(uploaded_file.getbuffer())

        
    if st.button("Send"):

        r=subprocess.run(["python", "file_scan_write.py"])
        st.write(r)
    
    
def Link_Analyzer():
    import vt
    apikey=open("apikey.txt","r").read()
    url="http://testphp.vulnweb.com"
    url=st.text_input("URL","http://myetherevvalliet.com/")
    with vt.Client(apikey) as client:
        try:
            st.write(f"Scanning URL: {url}")
            url_obj = client.get_object(f"/urls/{vt.url_id(url)}")
            item=url_obj
            total_clean = sum(item.last_analysis_stats.values())
            num_spaces = 100 - len(item.url) if len(item.url) < 100 else 10
            st.write(
          f'{item.url}{" " * num_spaces}'
          f'{item.last_analysis_stats["malicious"]}/{total_clean}'
            )
            st.write(item.last_analysis_stats)
        except KeyboardInterrupt:
            st.write("\nKeyboard interrupt. Closing.")
        except Exception as e:
            st.write(f"Error: {e}")
        finally:
            client.close()
    return
def File_Stat_Viewer():
    import streamlit as st
    import pandas as pd

    # Load CSV file
    csv_file = "analysis_results.csv"  # Change to your file path
    df = pd.read_csv(csv_file)

    # Streamlit UI
    st.title("VirusTotal Analysis Results")
    st.write("Displaying VirusTotal scan statistics from CSV.")

    # Show raw data
    st.dataframe(df)

    # Aggregate statistics for better visualization
    st.subheader("Analysis Statistics Overview")

    # Exclude Filename & Analysis ID for summing numerical columns
    stats_columns = df.columns[2:]
    stats_summary = df[stats_columns].sum()

    # Display bar chart
    st.bar_chart(stats_summary)


    return

page_names_to_funcs = {
    "Link Analyzer":Link_Analyzer,
    "Upload Files": Upload_Files,
    "Home": Home,
    "File Stats": File_Stat_Viewer,
}

st.sidebar.image("./logo.jpg")
demo_name = st.sidebar.selectbox("What you want to do?", page_names_to_funcs.keys())
page_names_to_funcs[demo_name]()
