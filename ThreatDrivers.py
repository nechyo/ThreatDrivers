import streamlit as st
import pandas as pd
import plotly.express as px
from tqdm import tqdm
import requests
import json
import sys
import os
import numpy as np

# Streamlit app configuration
st.set_page_config(page_title='ThreatDrivers Dashboard', layout='wide')

collection_id = '06818046399c5674eeb31f66e8eda0265a4f8bb4d4cc00b2da3f5955ac171458'
data_file = 'all_collection_metadata.json'

# Load existing data or fetch via API
if os.path.exists(data_file):
    loading_message = st.info("Loading previously saved data...")
    with open(data_file, 'r', encoding='utf-8') as f:
        all_data = json.load(f)
else:
    st.sidebar.header('Settings')
    api_key = st.sidebar.text_input('Enter your VirusTotal API Key:', type='password')
    if not api_key:
        st.warning("Please enter API Key to proceed.")
        st.stop()

    # VirusTotal request URL and headers
    base_url = f'https://www.virustotal.com/api/v3/collections/{collection_id}/files'
    headers = {
        'x-apikey': api_key
    }


    loading_message = st.info("Data file not found. Fetching data from VirusTotal API now...")
    all_data = []
    next_url = base_url  # Initial URL

    with tqdm(desc="Fetching Data", unit="page") as pbar:
        while next_url:
            response = requests.get(next_url, headers=headers)

            if response.status_code != 200:
                st.error(f'Request failed with status code: {response.status_code}')
                st.stop()

            # Parse JSON response
            data = response.json()
            page_data = data.get("data", [])
            all_data.extend(page_data)  # Accumulate data

            # Move to next URL
            next_url = data.get("links", {}).get("next")
            pbar.update(1)  # Update progress bar

    # Save collected data to a file
    with open(data_file, 'w', encoding='utf-8') as f:
        json.dump(all_data, f, ensure_ascii=False, indent=4)
    st.success('Data saved to "all_collection_metadata.json"')

loading_message.empty()
# Total file count and detection status
total_files = len(all_data)
total_detected = 0
total_undetected = 0

# Populate file metadata
data_rows = []
antivirus_counts_detected = {"Microsoft": 0, "AhnLab-V3": 0, "Avast": 0, "BitDefender": 0, "Kaspersky": 0}
antivirus_counts_undetected = {"Microsoft": 0, "AhnLab-V3": 0, "Avast": 0, "BitDefender": 0, "Kaspersky": 0}
import_counts = {}
signer_counts = {}
vaild_signer_counts = {}

for ioc in all_data:
    if "attributes" not in ioc:
        continue
    
    attributes = ioc["attributes"]
    sha256 = attributes.get("sha256", "N/A")
    file_type = attributes.get("type_tag", "N/A")
    magic = attributes.get("magic", "N/A")
    size = attributes.get("size", "N/A")
    creation_date = attributes.get("creation_date", "N/A")
    last_analysis_date = attributes.get("last_analysis_date", "N/A")
    reputation = attributes.get("reputation", "N/A")
    tags = ', '.join(attributes.get("tags", []))
    results = attributes.get("last_analysis_results", {})
    import_list = attributes["pe_info"].get("import_list", [])
    signature_info = attributes.get("signature_info", {})

    # Summary of detection status
    detected_count = sum(1 for result in results.values() if result.get("category") == "malicious")
    undetected_count = len(results) - detected_count

    # Update detection status counts
    if detected_count > 0:
        total_detected += 1
    else:
        total_undetected += 1

    # Count detections by specific antivirus engines
    for engine_name, result in results.items():
        if engine_name in antivirus_counts_detected:
            if result.get("category") == "malicious":
                antivirus_counts_detected[engine_name] += 1
            else:
                antivirus_counts_undetected[engine_name] += 1

    # Count imports and signers
    for import_item in import_list:
        library_name = import_item.get("library_name", "Unknown")
        #if library_name != "ntoskrnl.exe": continue
        for imported_function in import_item.get("imported_functions"):
            import_counts[imported_function] = import_counts.get(imported_function, 0) + 1

    for signer in signature_info:
        signer_name = signature_info.get("signers") if isinstance(signature_info, dict) else "Unknown"
        signer_counts[signer_name] = signer_counts.get(signer_name, 0) + 1
        if len(signature_info.get('signers details', '')) >= 1: # 다중 서명
            if signature_info.get('signers details', '')[0].get("status") == "Valid":
                vaild_signer = signature_info.get('signers details', '')[0]
                vaild_signer_name = vaild_signer.get("name") if isinstance(vaild_signer, dict) else "Unknown"
                vaild_signer_counts[vaild_signer_name] = vaild_signer_counts.get(vaild_signer_name, 0) + 1

    # Add file metadata to list
    data_rows.append([sha256, file_type, magic, size, creation_date, last_analysis_date, reputation, tags, detected_count, undetected_count])

# Convert collected data into DataFrame
df = pd.DataFrame(data_rows, columns=['SHA256', 'File Type', 'Magic', 'Size', 'Creation Date', 'Last Analysis Date', 'Reputation', 'Tags', 'Detected', 'Undetected'])

# Render the results using Streamlit
st.header("ThreatDrivers Analysis Dashboard")

# Main Dashboard Overview
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Files", total_files)
col2.metric("Detected Files", total_detected)
col3.metric("Undetected Files", total_undetected)
col4.metric("Average File Size (KB)", round(df['Size'].replace('N/A', np.nan).dropna().astype(int).mean() / 1024, 2))

st.write("## Detection Visualization")
detection_fig = px.bar(
    x=['Detected', 'Undetected'], 
    y=[total_detected, total_undetected],
    labels={'x': 'Detection Status', 'y': 'Number of Files'},
    title='Detection',
)
st.plotly_chart(detection_fig)

# Plotting a bar chart for import library usage focusing on functions
st.write("## Import Library Usage Visualization")
import_data = pd.DataFrame({
    'Library Name': list(import_counts.keys()),
    'Number of Imports': list(import_counts.values())
})
import_data.sort_values(by=['Number of Imports'], axis=0, ascending=False, inplace=True)
import_fig = px.bar(
    import_data, 
    y='Library Name', 
    x='Number of Imports', 
    orientation='h',
    title='Import Library Usage Summary',
    color='Number of Imports',
    color_continuous_scale='teal'
)
st.plotly_chart(import_fig)

# Plotting a bar chart for file signers focusing on signer names
st.write("## File Signers Visualization")
signer_data = pd.DataFrame({
    'Signer Name': list(signer_counts.keys()),
    'Number of Signatures': list(signer_counts.values())
})
signer_data.sort_values(by=['Number of Signatures'], axis=0, ascending=False, inplace=True)
signer_fig = px.bar(
    signer_data,
    y='Signer Name',
    x='Number of Signatures',
    orientation='h',
    title='File Signers',
    color='Number of Signatures',
)
st.plotly_chart(signer_fig)

# Creating a table for valid signers
st.write("## Valid File Signers Visualization")
valid_signers_data = pd.DataFrame({
    'Valid Signer Name': list(vaild_signer_counts.keys()),
    'Number of Valid Signatures': list(vaild_signer_counts.values())
})

valid_signers_data.sort_values(by=['Number of Valid Signatures'], axis=0, ascending=False, inplace=True)
valid_signer_fig = px.bar(
    valid_signers_data,
    y='Valid Signer Name',
    x='Number of Valid Signatures',
    orientation='h',
    title='Valid File Signers',
    color='Number of Valid Signatures',
)
st.plotly_chart(valid_signer_fig)

# Additional Visualization: File Size Distribution
st.write("## File Size Distribution")
file_sizes = df['Size'].replace('N/A', np.nan).dropna().astype(int) / 1024  # Convert to KB
file_size_fig = px.histogram(
    file_sizes,
    nbins=30,
    title='File Size Distribution',
    labels={'value': 'File Size (KB)', 'count': 'Number of Files'},
    color_discrete_sequence=['gray']
)
st.plotly_chart(file_size_fig)

# Plotting a bar chart for antivirus detection summary
st.write("## Antivirus Detection Visualization")
antivirus_data = pd.DataFrame({
    'Antivirus Engine': list(antivirus_counts_detected.keys()),
    'Detected': list(antivirus_counts_detected.values()),
    'Undetected': list(antivirus_counts_undetected.values())
})
antivirus_fig = px.bar(
    antivirus_data.melt(id_vars='Antivirus Engine', value_vars=['Detected', 'Undetected']),
    x='Antivirus Engine',
    y='value',
    color='variable',
    barmode='group',
    title='Antivirus Detection by Engines',
    labels={'value': 'Number of Files', 'variable': 'Detection Status'},
    color_discrete_sequence=['#FF6F61', '#6B8E23'],
)
st.plotly_chart(antivirus_fig)

# Display the data as a detailed table
#st.sidebar.header("Detail View Settings")
#show_table = st.sidebar.checkbox('Show Detailed File Analysis Table', value=False)

#if show_table:
#    st.write("## File Analysis Summary Table")
#    st.dataframe(df.style.set_properties(**{'font-size': '10pt', 'max-height': '400px'}))
    
# Conclusion message
st.success("Analysis complete.")
