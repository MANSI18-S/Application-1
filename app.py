import streamlit as st
from pymongo import MongoClient
import pandas as pd

# --- APP CONFIG ---
st.set_page_config(page_title="Stocks Portfolio", page_icon="📊", layout="wide")

# --- CONNECT TO MONGO ---
@st.cache_resource
def get_mongo_client():
    mongo_uri = st.secrets["mongo"]["uri"]
    return MongoClient(mongo_uri)

client = get_mongo_client()
db = client["portfolio_db"]
users_col = db["users"]

# --- AUTHENTICATION ---
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "mansi1515"

st.title("📊 Stocks Portfolio Login")

# --- LOGIN FORM ---
login_choice = st.sidebar.radio("Select Option", ["Login", "Register"])

if login_choice == "Register":
    st.subheader("Create a New Account")
    new_user = st.text_input("Enter username")
    new_pass = st.text_input("Enter password", type="password")
    if st.button("Register"):
        if users_col.find_one({"username": new_user}):
            st.warning("User already exists!")
        else:
            users_col.insert_one({"username": new_user, "password": new_pass, "stocks": []})
            st.success("Account created successfully! Please log in.")

elif login_choice == "Login":
    st.subheader("Login to Your Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            st.success("Welcome, Admin!")
            st.subheader("All User Data")
            users = list(users_col.find({}, {"_id": 0, "password": 0}))
            if users:
                st.dataframe(pd.DataFrame(users))
            else:
                st.info("No user data found.")
        else:
            user = users_col.find_one({"username": username, "password": password})
            if user:
                st.success(f"Welcome, {username}!")
                st.subheader("Your Portfolio")
                user_stocks = user.get("stocks", [])
                st.write(pd.DataFrame(user_stocks) if user_stocks else "No stocks added yet.")

                with st.expander("➕ Add Stock"):
                    symbol = st.text_input("Stock Symbol")
                    quantity = st.number_input("Quantity", min_value=1)
                    price = st.number_input("Purchase Price", min_value=0.0)
                    if st.button("Add Stock"):
                        users_col.update_one(
                            {"username": username},
                            {"$push": {"stocks": {"symbol": symbol, "quantity": quantity, "price": price}}}
                        )
                        st.success("Stock added successfully!")
            else:
                st.error("Invalid username or password.")
