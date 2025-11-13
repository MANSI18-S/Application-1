import streamlit as st
from mongo_helper import create_user, authenticate_user

st.set_page_config(page_title="Stock Portfolio App", layout="centered")

st.title("📈 Stock Portfolio Dashboard")

# Session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None

def login_page():
    st.subheader("🔐 Login to your account")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        success, role = authenticate_user(username, password)
        if success:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.role = role
            st.success(f"Welcome {username}!")
            st.experimental_rerun()
        else:
            st.error("Invalid credentials")

    st.info("Don't have an account? Create one below 👇")
    if st.button("Register New User"):
        st.session_state.show_register = True
        st.experimental_rerun()

def register_page():
    st.subheader("🧾 Register New Account")

    username = st.text_input("New Username")
    password = st.text_input("New Password", type="password")
    confirm = st.text_input("Confirm Password", type="password")

    if password and confirm and password != confirm:
        st.error("Passwords do not match")

    if st.button("Create Account"):
        if password == confirm:
            success, msg = create_user(username, password)
            if success:
                st.success(msg)
                st.session_state.show_register = False
                st.experimental_rerun()
            else:
                st.error(msg)

    if st.button("Back to Login"):
        st.session_state.show_register = False
        st.experimental_rerun()

def logout():
    st.session_state.logged_in = False
    st.session_sta_
