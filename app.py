import streamlit as st
from pymongo import MongoClient
import bcrypt

# ------------------- MongoDB Connection -------------------
@st.cache_resource
def get_db():
    uri = st.secrets["mongo"]["uri"]
    db_name = st.secrets["mongo"]["db_name"]
    client = MongoClient(uri)
    return client[db_name]

# ------------------- User Management -------------------
def create_user(username, password, role="user"):
    db = get_db()
    users = db["users"]
    if users.find_one({"username": username}):
        return False, "Username already exists"
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    users.insert_one({"username": username, "password": hashed, "role": role})
    return True, "User created successfully"

def authenticate_user(username, password):
    db = get_db()
    user = db["users"].find_one({"username": username})
    if user and bcrypt.checkpw(password.encode(), user["password"]):
        return True, user["role"]
    return False, None

# ------------------- Portfolio Data -------------------
def get_portfolios(username=None, is_admin=False):
    db = get_db()
    portfolios = db["portfolios"]
    if is_admin:
        return list(portfolios.find({}))
    return list(portfolios.find({"username": username}))

def add_portfolio(username, data):
    db = get_db()
    portfolios = db["portfolios"]
    portfolios.insert_one({"username": username, "data": data})

# ------------------- UI Components -------------------
st.set_page_config(page_title="Stock Portfolio App", layout="centered")
st.title("📈 Stock Portfolio Dashboard")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None
    st.session_state.page = "login"

# ----------- Login Page -----------
def login_page():
    st.subheader("🔐 Login")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        success, role = authenticate_user(username, password)
        if success:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.role = role
            st.success(f"Welcome {username}!")
            st.session_state.page = "portfolio"
            st.experimental_rerun()
        else:
            st.error("Invalid username or password")

    if st.button("Register New Account"):
        st.session_state.page = "register"
        st.experimental_rerun()

# ----------- Register Page -----------
def register_page():
    st.subheader("🧾 Register New Account")

    username = st.text_input("Create Username")
    password = st.text_input("Create Password", type="password")
    confirm = st.text_input("Confirm Password", type="password")

    if st.button("Create Account"):
        if not username or not password:
            st.error("Please enter all fields")
        elif password != confirm:
            st.error("Passwords do not match")
        else:
            success, msg = create_user(username, password)
            if success:
                st.success(msg)
                st.session_state.page = "login"
                st.experimental_rerun()
            else:
                st.error(msg)

    if st.button("Back to Login"):
        st.session_state.page = "login"
        st.experimental_rerun()

# ----------- Portfolio Page -----------
def portfolio_page():
    st.sidebar.title(f"👋 {st.session_state.username}")
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.role = None
        st.session_state.page = "login"
        st.experimental_rerun()

    is_admin = st.session_state.role == "admin"

    if is_admin:
        st.subheader("🛠 Admin Panel - All User Portfolios")
    else:
        st.subheader("📊 Your Portfolio")

    portfolios = get_portfolios(
        username=st.session_state.username, is_admin=is_admin
    )

    if portfolios:
        for p in portfolios:
            st.write(f"**User:** {p['username']}")
            st.json(p.get("data", {}))
            st.divider()
    else:
        st.info("No portfolio data found.")

    st.write("---")
    st.subheader("➕ Add Portfolio Entry")
    stock_name = st.text_input("Stock Name")
    stock_value = st.number_input("Stock Value", min_value=0.0, step=0.01)
    if st.button("Add Stock"):
        add_portfolio(
            st.session_state.username,
            {"stock": stock_name, "value": stock_value}
        )
        st.success("Stock added successfully!")
        st.experimental_rerun()

# ------------------- Routing -------------------
if not st.session_state.logged_in:
    if st.session_state.page == "login":
        login_page()
    elif st.session_state.page == "register":
        register_page()
else:
    portfolio_page()
