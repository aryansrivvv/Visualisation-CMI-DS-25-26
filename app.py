import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

st.set_page_config(page_title="NSL-KDD Inspector", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    /* 1. Main Background */
    .stApp {
        background-color: #0E1117;
    }

    /* 2. Metrics (Top Cards) Styling */
    div[data-testid="stMetric"] {
        background-color: rgba(28, 31, 46, 0.7);
        border: 1px solid #303030;
        padding: 15px 25px; /* More internal padding */
        border-radius: 15px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        transition: transform 0.2s ease-in-out;
    }
    div[data-testid="stMetric"]:hover {
        transform: scale(1.02);
        border: 1px solid #00CC96;
        box-shadow: 0 0 15px rgba(0, 204, 150, 0.2);
    }

    /* 3. TABS STYLING - THE FIX */
    /* Container: Adds space between the tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px; 
        background-color: transparent;
        padding-bottom: 10px;
    }

    /* Inactive Tabs: distinct cards with plenty of space */
    .stTabs [data-baseweb="tab"] {
        height: 65px; /* Fixed height for consistency */
        flex: 1; /* Makes all tabs equal width */
        white-space: nowrap; /* Prevents text from squishing */
        background-color: #161a25; 
        border: 1px solid #303030;
        border-radius: 10px; /* Rounded corners */
        padding: 0px 20px; /* Horizontal breathing room */
        color: #b0b0b0;
        font-weight: 500;
        font-size: 16px; /* Larger text */
        transition: all 0.3s ease;
    }

    /* Hover State */
    .stTabs [data-baseweb="tab"]:hover {
        background-color: #212534;
        border-color: #606060;
        color: #ffffff;
    }

    /* Active Tab: Bright, glowing, and clearly selected */
    .stTabs [aria-selected="true"] {
        background-color: #00CC96 !important;
        color: #ffffff !important;
        border: 1px solid #00CC96 !important;
        box-shadow: 0 0 15px rgba(0, 204, 150, 0.4); /* The Glow */
        font-weight: 700;
        transform: translateY(-2px); /* Slight lift effect */
    }
    
    /* Remove the default underline Streamlit adds */
    .stTabs [data-baseweb="tab-highlight"] {
        display: none;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_data
def load_data():
    columns = ["duration","protocol_type","service","flag","src_bytes",
        "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
        "logged_in","num_compromised","root_shell","su_attempted","num_root",
        "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
        "is_host_login","is_guest_login","count","srv_count","serror_rate",
        "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
        "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
        "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
        "dst_host_rerror_rate","dst_host_srv_rerror_rate","label", "difficulty"]
    try:
        url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
        df = pd.read_csv(url, header=None, names=columns)
    except Exception as e:
        st.error(f"Could not load data: {e}")
        return pd.DataFrame()

    # label: 'normal' vs 'attack'
    df['class'] = df['label'].apply(lambda x: 'Normal' if x == 'normal' else 'Attack')
    
    # Map specific attacks to categories (Dos, Probe, R2L, U2R) 
    attack_map = {
        'neptune': 'DoS', 'warezclient': 'R2L', 'ipsweep': 'Probe', 'portsweep': 'Probe',
        'teardrop': 'DoS', 'nmap': 'Probe', 'satan': 'Probe', 'smurf': 'DoS',
        'pod': 'DoS', 'back': 'DoS', 'guess_passwd': 'R2L', 'ftp_write': 'R2L',
        'multihop': 'R2L', 'rootkit': 'U2R', 'buffer_overflow': 'U2R', 'normal': 'Normal'
    }
    df['attack_category'] = df['label'].apply(lambda x: attack_map.get(x, 'Other'))
    return df

df = load_data()

def gen_sankey(df, cat_cols=[], value_col=None, title='Sankey Diagram'):
    labelList = []
    colorList = []
    for cat in cat_cols:
        labelListTemp = list(set(df[cat].values))
        colorList.append(labelListTemp)
        labelList = labelList + labelListTemp
    labelList = list(dict.fromkeys(labelList))
    color_map = {'Normal': '#00CC96', 'Attack': '#EF553B', 'tcp': '#636EFA', 'udp': '#AB63FA'}
    node_colors = [color_map.get(lab, "rgba(200,200,200, 0.8)") for lab in labelList]
    sourceTargetDf = pd.DataFrame(columns=['source', 'target', 'value'])
    
    for i in range(len(cat_cols) - 1):
        tempDf = df.groupby([cat_cols[i], cat_cols[i + 1]]).agg({value_col: 'count'}).reset_index()
        tempDf.columns = ['source', 'target', 'value']
        tempDf['sourceID'] = tempDf['source'].apply(lambda x: labelList.index(x))
        tempDf['targetID'] = tempDf['target'].apply(lambda x: labelList.index(x))
        sourceTargetDf = pd.concat([sourceTargetDf, tempDf])
    fig = go.Figure(data=[go.Sankey(
        node=dict(
            pad=15,
            thickness=20,
            line=dict(color="black", width=0.5),
            label=labelList,
            color=node_colors
        ),
        link=dict(
            source=sourceTargetDf['sourceID'],
            target=sourceTargetDf['targetID'],
            value=sourceTargetDf['value']
        )
    )])
    fig.update_layout(title_text=title, font_size=12, height=600, paper_bgcolor="rgba(0,0,0,0)")
    return fig

st.sidebar.header("🎛️ Control Panel")
st.sidebar.write("Filter the dataset to explore specific traffic patterns.")

selected_protocol = st.sidebar.multiselect(
    "Select Protocols", df['protocol_type'].unique(), default=df['protocol_type'].unique()
)

selected_service = st.sidebar.multiselect(
    "Select Services (Top 10)", df['service'].value_counts().head(10).index.tolist(), 
    default=df['service'].value_counts().head(5).index.tolist()
)

filtered_df = df[
    (df['protocol_type'].isin(selected_protocol)) & 
    (df['service'].isin(selected_service))
]

st.title("🛡️ NSL-KDD Network Traffic Forensics")
st.markdown("Interactive analysis of network intrusion patterns.")

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("Total Packets", f"{len(filtered_df):,}")
with col2:
    attack_rate = (filtered_df['class'] == 'Attack').mean() * 100
    st.metric("Attack Rate", f"{attack_rate:.2f}%", delta_color="inverse")
with col3:
    top_attack = filtered_df[filtered_df['class']=='Attack']['label'].mode()[0] if attack_rate > 0 else "None"
    st.metric("Most Frequent Attack", top_attack)
with col4:
    avg_duration = filtered_df['duration'].mean()
    st.metric("Avg Duration", f"{avg_duration:.2f}s")

st.markdown("---")

# 2. Interactive Visualizations
tab1, tab2, tab3, tab4 = st.tabs(["📊 Traffic Overview", "🕸️ Attack Hierarchy", "🔍 Feature Correlation", "🌊 Traffic Flow"])

with tab1:
    col_a, col_b = st.columns([2, 1])
    
    with col_a:
        st.subheader("Traffic Volume by Service")
        # Bar chart with color distinguishing Normal vs Attack
        fig_bar = px.bar(
            filtered_df.groupby(['service', 'class']).size().reset_index(name='count'), 
            x='service', y='count', color='class',
            color_discrete_map={'Normal': '#00CC96', 'Attack': '#EF553B'},
            title="Service Usage: Normal vs Attack",
            barmode='stack'
        )
        fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig_bar, use_container_width=True)
        
    with col_b:
        st.subheader("Protocol Distribution")
        fig_pie = px.pie(filtered_df, names='protocol_type', hole=0.4, title="Protocol Share")
        fig_pie.update_layout(paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig_pie, use_container_width=True)

with tab2:
    st.subheader("Sunburst Chart: Attack Classification")
    st.write("Drill down from **Traffic Class** → **Attack Category** → **Specific Attack Name**.")
    
    # Prepare hierarchical data
    # Only showing Attack data for deeper forensics
    attack_df = filtered_df[filtered_df['class'] == 'Attack']
    
    if not attack_df.empty:
        fig_sun = px.sunburst(
            attack_df, 
            path=['attack_category', 'label'], 
            values='count',
            color='attack_category',
            title="Attack Composition Hierarchy"
        )
        fig_sun.update_layout(height=600)
        st.plotly_chart(fig_sun, use_container_width=True)
    else:
        st.info("No attack data in current selection.")
        
    

with tab3:
    st.subheader("3D Feature Scatter Plot")
    st.write("Visualize the relationship between Source Bytes, Destination Bytes, and Duration.")
    
    # Subsample for performance if data is huge
    sample_df = filtered_df.sample(min(1000, len(filtered_df)))
    
    fig_3d = px.scatter_3d(
        sample_df, x='src_bytes', y='dst_bytes', z='duration',
        color='class', symbol='protocol_type',
        log_x=True, log_y=True, # Log scale usually helps with Byte data
        color_discrete_map={'Normal': '#00CC96', 'Attack': '#EF553B'},
        title="Multivariate Traffic Analysis (Log Scale)"
    )
    st.plotly_chart(fig_3d, use_container_width=True)
    st.markdown("""
    <div style='background-color: #161a25; padding: 15px; border-radius: 10px; border: 1px solid #303030; margin-top: 10px;'>
        <h5 style='color: #00CC96; margin-top: 0;'>💡 How to Read This Chart</h5>
        <p style='color: #d0d0d0; font-size: 14px; line-height: 1.5;'>
            This 3D visualization reveals traffic anomalies by plotting <b>Source Bytes</b> (X), 
            <b>Destination Bytes</b> (Y), and <b>Duration</b> (Z).
        </p>
        <ul style='color: #b0b0b0; font-size: 14px; padding-left: 20px;'>
            <li style="margin-bottom: 5px;">
                <b>Why Log Scale?</b> Network data has extreme variance (some packets are 0 bytes, others are millions). 
                The log scale "compresses" these huge differences so you can see both small and large packets in the same view.
            </li>
            <li>
                <b>What to look for:</b> "Normal" traffic (Green) typically forms tight, predictable clusters. 
                "Attacks" (Red) often appear as <b>outliers</b>—floating high up (long duration) or far to the right (massive data transfer)—away from the main group.
            </li>
        </ul>
    </div>
    """, unsafe_allow_html=True)
    st.markdown("---")
    col_radar1, col_radar2 = st.columns([1, 2])

    with col_radar1:
        st.subheader("🕸️ Traffic Profile Scanner")
        st.write("Compare the average feature footprint of Attacks vs Normal traffic.")
        
        # Select features to compare on the radar (Normalized)
        radar_feats = ['duration', 'src_bytes', 'dst_bytes', 'count', 'srv_count', 'same_srv_rate']
        
        # Normalize the data for the radar chart so big numbers don't squash small ones
        scaler_df = df[radar_feats + ['class']].copy()
        for col in radar_feats:
            scaler_df[col] = scaler_df[col] / scaler_df[col].max()
        
        # Group by class
        radar_data = scaler_df.groupby('class')[radar_feats].mean().reset_index()
        
        # Melt for Plotly
        radar_melt = radar_data.melt(id_vars='class', var_name='theta', value_name='r')

    with col_radar2:
        fig_radar = px.line_polar(
            radar_melt, r='r', theta='theta', color='class', line_close=True,
            color_discrete_map={'Normal': '#00CC96', 'Attack': '#EF553B'},
            markers=True,
            title="Attack Signature vs Normal Baseline (Normalized)"
        )
        fig_radar.update_layout(
            polar=dict(bgcolor="rgba(0,0,0,0)"),
            paper_bgcolor="rgba(0,0,0,0)",
            legend=dict(orientation="h", y=-0.1)
        )
        fig_radar.update_traces(fill='toself') # Fills the area with color
        st.plotly_chart(fig_radar, use_container_width=True)
    
    st.subheader("🔥 Feature Correlation Heatmap")
    # Select numeric columns only
    numeric_df = filtered_df.select_dtypes(include=['float64', 'int64']).iloc[:, :10] # limit to first 10 for speed
    corr = numeric_df.corr()

    fig_corr = px.imshow(
        corr, 
        text_auto=True, 
        aspect="auto",
        color_continuous_scale='RdBu_r', # Red-Blue diverging scale
        title="Feature Correlation Matrix"
    )
    st.plotly_chart(fig_corr, use_container_width=True)


with tab4:
    st.subheader("Traffic Flow: Protocol → Service → Classification")
    st.write("Trace how different protocols and services contribute to attacks.")
    
    # 1. Limit data to prevent "spaghetti" mess
    # We take top 10 services, label others as 'Other'
    sankey_df = filtered_df.copy()
    top_services = sankey_df['service'].value_counts().nlargest(10).index
    sankey_df['service_grouped'] = sankey_df['service'].apply(lambda x: x if x in top_services else 'Other_Service')
    
    # 2. Define the flow path
    # Path: Protocol Type -> Service -> Class (Normal/Attack)
    fig_sankey = gen_sankey(
        sankey_df, 
        cat_cols=['protocol_type', 'service_grouped', 'class'], 
        value_col='count', 
        title="Network Traffic Pathways"
    )
    
    st.plotly_chart(fig_sankey, use_container_width=True)

# --- ML PREDICTION SECTION ---
st.markdown("---")
st.markdown("### 🛡️ Adversarial Sandbox")
st.caption("Use this module to simulate network traffic parameters and test the IDS detection logic.")

c1, c2 = st.columns([1, 3])

with c1:
    st.info("Train a model on the fly with the current filtered data.")
    if st.button("Train Model"):
        # Simple preprocessing
        le = LabelEncoder()
        
        # Prepare small training set
        train_cols = ['duration', 'src_bytes', 'dst_bytes', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins']
        X = filtered_df[train_cols].copy()
        y = filtered_df['class'].apply(lambda x: 1 if x == 'Attack' else 0)
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)
        
        clf = RandomForestClassifier(n_estimators=50)
        clf.fit(X_train, y_train)
        
        score = clf.score(X_test, y_test)
        st.success(f"Model Accuracy: {score:.2%}")
        
        # Store model in session state for reuse
        st.session_state['model'] = clf
        st.session_state['train_cols'] = train_cols

with c2:
    if 'model' in st.session_state:
        st.write("### Test a Packet")
        c_a, c_b, c_c = st.columns(3)
        p_dur = c_a.number_input("Duration", value=0)
        p_src = c_b.number_input("Src Bytes", value=200)
        p_dst = c_c.number_input("Dst Bytes", value=5000)
        
        # Check prediction
        if st.button("Predict"):
            input_data = pd.DataFrame([[p_dur, p_src, p_dst, 0, 0, 0, 0]], columns=st.session_state['train_cols'])
            prediction = st.session_state['model'].predict(input_data)[0]
            if prediction == 1:
                st.error("⚠️ ALERT: Malicious Traffic Detected!")
            else:
                st.success("✅ Traffic appears Normal.")


st.sidebar.markdown("---")
st.sidebar.subheader("📥 Export Data")
csv = filtered_df.to_csv(index=False).encode('utf-8')
st.sidebar.download_button(
    label="Download Filtered Dataset",
    data=csv,
    file_name='nsl_kdd_filtered.csv',
    mime='text/csv',
)