# 🛡️ NSL-KDD Network Intrusion Detection System
### An Interactive Forensic Dashboard for Cybersecurity Analysis

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28%2B-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![Plotly](https://img.shields.io/badge/Plotly-Interactive-3F4F75?style=for-the-badge&logo=plotly&logoColor=white)
![Status](https://img.shields.io/badge/Status-Live-success?style=for-the-badge)

> **"Turning raw packet data into actionable forensic insights."**

This dashboard provides a comprehensive interface for analyzing the **NSL-KDD dataset**, a benchmark dataset for network intrusion detection. It combines high-performance visualization with machine learning to help analysts identify traffic patterns, visualize attack signatures, and simulate potential threats.

---

## 🔗 Live Demo
**[Click Here to Launch the App](https://nsl-kdd-dashboard.streamlit.app/)**

---

## ✨ Key Features

### 1. 🎛️ Intelligent Control Panel
Located in the sidebar, this module allows for real-time data slicing.
* **Protocol Filtering:** Isolate TCP, UDP, or ICMP traffic.
* **Service Selection:** Focus on specific services (HTTP, FTP, Private) to reduce noise.
* **Export Capability:** Download the filtered subset of data as a CSV for external reporting.

### 2. 📊 Tab 1: Traffic Forensics
A high-level view of network health.
* **Packet Volume Analysis:** Stacked bar charts distinguishing "Normal" vs. "Attack" traffic across services.
* **Protocol Distribution:** Donut chart visualization of protocol usage shares.

### 3. 🕸️ Tab 2: Attack Hierarchy (Sunburst)
Drill down from high-level categories to specific attack signatures.
* **Interactive Sunburst Chart:** Click to explore the hierarchy: `Traffic Class` → `Attack Category` (DoS, Probe, R2L) → `Specific Attack` (Smurf, Neptune, Satan).
* **Contextual Insight:** Instantly see which attack types are dominating the network.

### 4. 🔍 Tab 3: Multivariate Analysis
Advanced statistical tools for the data scientist.
* **3D Scatter Plot (Log Scale):** Visualizes `Source Bytes` vs. `Destination Bytes` vs. `Duration`. Essential for spotting "outlier" attacks that drift away from the "Normal" traffic cluster.
* **Radar Chart (Spider Plot):** A "fingerprint" scanner that compares the average shape of an attack against normal traffic baselines.
* **Correlation Heatmap:** Identifies which network features (e.g., `srv_count`, `dst_host_count`) move together.

### 5. 🌊 Tab 4: Traffic Flow (Sankey)
* **Flow Visualization:** A Sankey diagram tracing the journey of packets from **Protocol** → **Service** → **Final Classification**.
* **Root Cause Analysis:** Visually answer questions like *"Which services are the primary vectors for DoS attacks?"*

### 6. 🧪 Adversarial Sandbox (ML Simulator)
A "What-If" analysis tool powered by a Random Forest Classifier.
* **Real-time Training:** Trains a lightweight model on the fly using currently filtered data.
* **Threat Simulation:** Manually input packet parameters (Duration, Bytes, etc.) to test if the IDS flags them as malicious. Used for **Boundary Testing** and model verification.

---

## 🛠️ Technical Architecture

| Component | Technology Used | Purpose |
| :--- | :--- | :--- |
| **Frontend** | Streamlit | UI Layout, Glassmorphism CSS, Interaction |
| **Visualization** | Plotly Express / Graph Objects | 3D Charts, Sankey, Sunburst, Radar |
| **Data Processing** | Pandas | Data cleaning, filtering, and aggregation |
| **Machine Learning** | Scikit-Learn | Random Forest Classifier for the "Sandbox" |
| **Dataset** | NSL-KDD | Standard benchmark for Intrusion Detection |

---

## 🚀 Installation & Setup

To run this dashboard locally on your machine:

**1. Clone the Repository**
```bash
git clone [https://github.com/YOUR_USERNAME/nsl-kdd-dashboard.git](https://github.com/YOUR_USERNAME/nsl-kdd-dashboard.git)
cd nsl-kdd-dashboard



**2. Install Dependencies**

```bash
pip install -r requirements.txt

```

**3. Run the App**

```bash
streamlit run app.py

```

The application will open automatically in your browser at `http://localhost:8501`.

---

## 📂 Project Structure

```text
nsl-kdd-dashboard/
├── app.py               # Main application source code
├── requirements.txt     # Python dependencies
├── README.md            # Documentation
└── .gitignore           # Git ignore file

```

---

## 🔮 Future Roadmap

* [ ] **Deep Learning Integration:** Replace Random Forest with an LSTM or Autoencoder for anomaly detection.
* [ ] **Live Packet Capture:** Integrate `Scapy` to visualize real-time network traffic from the host machine.
* [ ] **PDF Reporting:** Auto-generate a forensic PDF report based on current filters.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

#### 👨‍💻 Created by [Aryan Srivastava]

*Connect with me on [LinkedIn]([https://linkedin.com/in/yourprofile](https://www.linkedin.com/in/aryan-srivastava-8782ba171/)). *

```

```
