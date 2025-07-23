import streamlit as st
import pandas as pd
import joblib

# Load model and encoders
model = joblib.load("model.pkl")
label_encoder = joblib.load("label_encoder.pkl")

# Load column order from training data
try:
    full_df = pd.read_csv("demo.csv")
    expected_columns = full_df.drop(columns=["label"]).columns.tolist()
except Exception as e:
    st.error(f"Could not load demo.csv or extract expected columns: {e}")
    st.stop()

# Streamlit UI
st.set_page_config(page_title="AI Traffic Classifier", layout="centered")
st.title("AI-Powered Network Traffic Analyzer")
st.markdown("Enter traffic flow data to predict the application or threat type.")

# Form input
with st.form("predict_form"):
    protocol = st.selectbox("Protocol", ["tcp", "udp", "icmp"])
    service = st.selectbox("Service", ["http", "ftp_data", "domain_u", "private", "ecr_i"])
    duration = st.number_input("Duration", min_value=0)
    src_bytes = st.number_input("Source Bytes", min_value=0)
    dst_bytes = st.number_input("Destination Bytes", min_value=0)
    flag = st.selectbox("TCP Flag", ["SF", "S0", "RSTR", "REJ"])
    land = st.selectbox("Land", [0, 1])
    wrong_fragment = st.number_input("Wrong Fragment Count", min_value=0)
    urgent = st.number_input("Urgent Packet Count", min_value=0)

    submitted = st.form_submit_button("Predict")

if submitted:
    try:
        # Create input DataFrame
        input_df = pd.DataFrame([{
            "duration": duration,
            "protocol_type": protocol,
            "service": service,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "flag": flag,
            "land": land,
            "wrong_fragment": wrong_fragment,
            "urgent": urgent
        }])

        # Reorder to match training column order
        input_df = input_df[expected_columns]

        # Encode categorical columns
        for col in input_df.columns:
            try:
                encoder = joblib.load(f"{col}_encoder.pkl")
                input_df[col] = encoder.transform(input_df[col])
            except FileNotFoundError:
                continue

        # Predict
        prediction = model.predict(input_df)[0]
        prediction_proba = model.predict_proba(input_df)[0][prediction]
        predicted_label = label_encoder.inverse_transform([prediction])[0]

        # Display result
        st.success(f"Prediction: {predicted_label}")
        st.info(f"Confidence: {prediction_proba:.2%}")

    except Exception as e:
        st.error(f"Prediction failed: {e}")

