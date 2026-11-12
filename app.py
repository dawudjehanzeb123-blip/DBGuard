
import streamlit as st
import pandas as pd
from io import BytesIO
from datetime import datetime
from html import escape

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

from database import (
    initialise_database,
    get_database_data,
    add_user,
    update_user,
    delete_user,
    record_change,
    get_change_history
)

# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="DBGuard | DWCipherLab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --------------------------------------------------
# DATABASE
# --------------------------------------------------

try:
    initialise_database()
    users, expected_permissions = get_database_data()
except Exception as error:
    st.error(f"Database connection error: {error}")
    st.stop()


# --------------------------------------------------
# ORIGINAL DESIGN
# --------------------------------------------------

st.markdown("""
<style>
.stApp {
    background-color: #111827;
    color: #E5E7EB;
}

[data-testid="stSidebar"] {
    background-color: #0B1220;
    border-right: 1px solid #293548;
}

[data-testid="stMetric"] {
    background-color: #1F2937;
    border: 1px solid #374151;
    padding: 18px;
    border-radius: 12px;
}

[data-testid="stMetricValue"],
[data-testid="stMetricValue"] div {
    color: #FFFFFF !important;
    font-weight: 700 !important;
}

[data-testid="stMetricLabel"],
[data-testid="stMetricLabel"] p {
    color: #D1D5DB !important;
    opacity: 1 !important;
}

.stButton > button {
    background-color: #263D36;
    color: #A7F3D0;
    border: 1px solid #356653;
    border-radius: 8px;
}

.stButton > button:hover {
    background-color: #315346;
    color: #D1FAE5;
    border-color: #4B8A70;
}

.stTextInput input,
.stSelectbox [data-baseweb="select"] > div {
    background-color: #1F2937;
    color: #E5E7EB;
    border-color: #374151;
    border-radius: 8px;
}

[data-testid="stExpander"] {
    background-color: #172233 !important;
    border: 1px solid #374151;
    border-radius: 10px;
}

[data-testid="stExpander"] details,
[data-testid="stExpander"] summary {
    background-color: #172233 !important;
    color: #E5E7EB !important;
}

[data-testid="stExpander"] summary p,
[data-testid="stExpander"] summary span {
    color: #E5E7EB !important;
}

[data-testid="stExpander"] [data-testid="stExpanderDetails"] {
    background-color: #172233 !important;
    color: #E5E7EB !important;
}

[data-testid="stExpander"] [data-testid="stExpanderDetails"] p {
    color: #E5E7EB !important;
}

[data-testid="stDataFrame"] {
    border: 1px solid #374151;
    border-radius: 10px;
}

[data-testid="stSidebar"] [data-testid="stRadio"] label {
    color: #E5E7EB !important;
    font-weight: 600;
    padding: 8px;
    border-radius: 8px;
}

[data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
    background-color: #263D36;
    color: #6EE7B7 !important;
}

[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) {
    background-color: #1F3A32;
    color: #6EE7B7 !important;
    border: 1px solid #356653;
}
</style>
""", unsafe_allow_html=True)


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

with st.sidebar:
    st.title("🛡️ DBGuard")
    st.caption("DWCipherLab")
    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "Dashboard",
            "Permission Findings",
            "User Management",
            "Change History",
            "About DBGuard",
        ],
    )

    st.divider()
    st.caption("MODE: PostgreSQL database")
    st.caption("Version 0.3 — Prototype")


st.title("🛡️ DBGuard")
st.caption("Database permission monitoring and risk assessment")


# --------------------------------------------------
# PERMISSION ASSESSMENT
# --------------------------------------------------

results = []

for user in users:
    username = user.get("username", "Unknown")
    role = user.get("role", "Unknown")
    actual = set(user.get("permissions") or [])
    expected = set(expected_permissions.get(role, []))

    missing = sorted(expected - actual)
    excessive = sorted(actual - expected)

    if excessive:
        risk = "HIGH"
        recommendation = (
            "Review and remove unexpected permissions if unnecessary."
        )
    elif missing:
        risk = "REVIEW REQUIRED"
        recommendation = (
            "Review missing permissions and confirm whether they should be restored."
        )
    else:
        risk = "OK"
        recommendation = "No permission issues detected."

    results.append({
        "Username": username,
        "Role": role,
        "Risk": risk,
        "Expected permissions": ", ".join(sorted(expected)) or "None",
        "Actual permissions": ", ".join(sorted(actual)) or "None",
        "Unexpected permissions": ", ".join(excessive) or "None",
        "Missing permissions": ", ".join(missing) or "None",
        "Recommendation": recommendation,
    })

df = pd.DataFrame(results, columns=[
    "Username",
    "Role",
    "Risk",
    "Expected permissions",
    "Actual permissions",
    "Unexpected permissions",
    "Missing permissions",
    "Recommendation",
])


# --------------------------------------------------
# PDF REPORT
# --------------------------------------------------

def create_pdf_report(dataframe):
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(
        "DBGuard Security Assessment",
        styles["Title"]
    ))
    elements.append(Paragraph(
        "Database Permission Security Report",
        styles["Normal"]
    ))
    elements.append(Spacer(1, 8))

    report_date = datetime.now().strftime("%d %B %Y | %H:%M")

    elements.append(Paragraph(
        f"<b>Generated:</b> {report_date}",
        styles["Normal"]
    ))
    elements.append(Spacer(1, 20))

    total_users = len(dataframe)
    high_risk = int((dataframe["Risk"] == "HIGH").sum())
    review = int((dataframe["Risk"] == "REVIEW REQUIRED").sum())
    no_unexpected = int(
        (dataframe["Unexpected permissions"] == "None").sum()
    )
    missing_users = int(
        (dataframe["Missing permissions"] != "None").sum()
    )

    elements.append(Paragraph(
        "1. Assessment Summary",
        styles["Heading2"]
    ))

    summary_data = [
        ["Metric", "Count"],
        ["Users assessed", str(total_users)],
        ["High risk", str(high_risk)],
        ["Needs review", str(review)],
        ["No unexpected", str(no_unexpected)],
        ["Users with missing permissions", str(missing_users)],
    ]

    summary_table = Table(summary_data, colWidths=[300, 100])

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263b35")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ]))

    elements.append(summary_table)
    elements.append(Spacer(1, 25))

    elements.append(Paragraph(
        "2. Permission Findings",
        styles["Heading2"]
    ))

    for _, finding in dataframe[dataframe["Risk"] != "OK"].iterrows():
        risk = finding["Risk"]
        risk_colour = "#B42318" if risk == "HIGH" else "#B7791F"

        elements.append(Paragraph(
            f"<b>User:</b> {escape(str(finding['Username']))} "
            f"&nbsp;&nbsp; <b>Role:</b> {escape(str(finding['Role']))}",
            styles["Normal"]
        ))

        elements.append(Paragraph(
            f'<font color="{risk_colour}"><b>Risk: {risk}</b></font>',
            styles["Normal"]
        ))

        details = [
            ["Expected permissions", finding["Expected permissions"]],
            ["Actual permissions", finding["Actual permissions"]],
            ["Unexpected permissions", finding["Unexpected permissions"]],
            ["Missing permissions", finding["Missing permissions"]],
            ["Recommendation", finding["Recommendation"]],
        ]

        details = [
            [escape(str(cell)) for cell in row]
            for row in details
        ]

        details_table = Table(details, colWidths=[150, 350])

        details_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CCCCCC")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF0ED")),
            ("PADDING", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))

        elements.append(details_table)
        elements.append(Spacer(1, 18))

    elements.append(Paragraph(
        "DBGuard by DWCipherLab",
        styles["Heading2"]
    ))

    elements.append(Paragraph(
        "Educational security prototype. This report is based on "
        "the permission data stored in the connected database.",
        styles["Italic"]
    ))

    doc.build(elements)
    buffer.seek(0)

    return buffer.getvalue()


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

if page == "Dashboard":

    if st.button("↻ Refresh assessment"):
        st.rerun()

    st.subheader("Security overview")

    total_users = len(df)
    high_risk = int((df["Risk"] == "HIGH").sum())
    review = int((df["Risk"] == "REVIEW REQUIRED").sum())
    ok = int((df["Unexpected permissions"] == "None").sum())

    missing_permissions = int(
        (df["Missing permissions"] != "None").sum()
    )

    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric("Users assessed", total_users)
    c2.metric("High risk", high_risk)
    c3.metric("Needs review", review)
    c4.metric("Missing permissions", missing_permissions)
    c5.metric("No unexpected", ok)

    security_score = max(
        0,
        100 - (high_risk * 30) - (review * 15)
    )

    st.divider()
    st.subheader("DBGuard Security Score")

    st.metric(
        label="Indicative Security Score",
        value=f"{security_score}/100",
        help="Prototype score based on detected permission findings."
    )

    st.progress(security_score / 100)

    if security_score >= 80:
        risk_level = "LOW"
        risk_colour = "green"
    elif security_score >= 60:
        risk_level = "MODERATE"
        risk_colour = "orange"
    elif security_score >= 40:
        risk_level = "HIGH"
        risk_colour = "red"
    else:
        risk_level = "CRITICAL"
        risk_colour = "red"

    st.markdown(
        f"**Overall risk level:** :{risk_colour}[{risk_level}]"
    )

    st.caption(
        "This is an indicative score based on permission findings, "
        "not a complete measure of database security."
    )

    st.divider()
    st.subheader("Risk distribution")

    risk_counts = df["Risk"].value_counts().reindex(
        ["HIGH", "REVIEW REQUIRED", "OK"],
        fill_value=0
    )

    st.bar_chart(risk_counts, horizontal=True)

    st.divider()
    st.subheader("Find users")

    search = st.text_input("🔎 Search by username or role")

    risk_filter = st.selectbox(
        "Filter by risk",
        ["All", "HIGH", "REVIEW REQUIRED", "OK"],
    )

    filtered = df.copy()

    if search:
        matches = (
            filtered["Username"].str.contains(search, case=False, na=False)
            | filtered["Role"].str.contains(search, case=False, na=False)
        )
        filtered = filtered[matches]

    if risk_filter != "All":
        filtered = filtered[filtered["Risk"] == risk_filter]

    st.dataframe(
        filtered,
        use_container_width=True,
        hide_index=True,
    )


# --------------------------------------------------
# PERMISSION FINDINGS
# --------------------------------------------------

elif page == "Permission Findings":

    st.subheader("Permission findings")

    findings = df[df["Risk"] != "OK"]

    high_risk = int((df["Risk"] == "HIGH").sum())
    review = int((df["Risk"] == "REVIEW REQUIRED").sum())
    ok = int((df["Risk"] == "OK").sum())

    st.markdown("### Severity summary")

    c1, c2, c3 = st.columns(3)

    c1.metric("🔴 High risk", high_risk)
    c2.metric("🟠 Needs review", review)
    c3.metric("🟢 No unexpected", ok)

    st.divider()
    st.subheader("Filter permission findings")

    risk_filter = st.selectbox(
        "Choose risk level",
        ["All findings", "HIGH", "REVIEW REQUIRED", "OK"]
    )

    if risk_filter == "All findings":
        filtered_findings = df
    else:
        filtered_findings = df[df["Risk"] == risk_filter]

    st.dataframe(
        filtered_findings,
        use_container_width=True,
        hide_index=True
    )

    st.divider()
    st.subheader("Export security report")

    csv_report = filtered_findings.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="⬇️ Download permission report (CSV)",
        data=csv_report,
        file_name="DBGuard_Permission_Report.csv",
        mime="text/csv",
    )

    pdf_report = create_pdf_report(df)

    st.download_button(
        label="📄 Download security report (PDF)",
        data=pdf_report,
        file_name="DBGuard_Security_Report.pdf",
        mime="application/pdf",
    )

    st.divider()

    if findings.empty:
        st.success("No unexpected permissions or review issues found.")
    else:
        for _, finding in findings.iterrows():
            with st.expander(
                f'{finding["Risk"]} — {finding["Username"]} '
                f'({finding["Role"]})'
            ):
                st.write("**Role:**", finding["Role"])
                st.write("**Expected permissions:**", finding["Expected permissions"])
                st.write("**Actual permissions:**", finding["Actual permissions"])
                st.write("**Unexpected permissions:**", finding["Unexpected permissions"])
                st.write("**Missing permissions:**", finding["Missing permissions"])
                st.write("**Recommended action:**", finding["Recommendation"])


# --------------------------------------------------
# USER MANAGEMENT
# --------------------------------------------------

elif page == "User Management":

    st.subheader("User Management")

    st.write("### Add a user")

    with st.form("add_user_form"):

        username = st.text_input("Username")

        role = st.selectbox(
            "Select database role",
            ["reader", "admin", "report_viewer"],
            key="add_role"
        )

        permissions = st.multiselect(
            "Select permissions",
            ["SELECT", "INSERT", "UPDATE", "DELETE"],
            key="add_permissions"
        )

        submitted = st.form_submit_button("Add User")

        if submitted:
            clean_username = username.strip()

            if not clean_username:
                st.error("Please enter a username.")

            elif any(
                user["username"].lower() == clean_username.lower()
                for user in users
            ):
                st.error("This username already exists.")

            else:
                try:
                    add_user(clean_username, role, permissions)

                    record_change(
                        "User added",
                        clean_username,
                        f"Role: {role}; permissions: "
                        f"{', '.join(permissions) if permissions else 'None'}"
                    )

                    st.success(f"User {clean_username} has been added.")
                    st.rerun()

                except Exception as error:
                    st.error(f"Unable to add user: {error}")

    st.divider()
    st.write("### Edit or delete an existing user")

    if not users:
        st.info("There are no users to edit or delete.")

    else:
        usernames = [user["username"] for user in users]

        selected_username = st.selectbox(
            "Choose a user",
            usernames,
            key="manage_selected_user"
        )

        selected_user = next(
            user for user in users
            if user["username"] == selected_username
        )

        with st.form("edit_user_form"):

            edited_username = st.text_input(
                "Username",
                value=selected_user["username"]
            )

            role_options = ["reader", "admin", "report_viewer"]
            current_role = selected_user.get("role", "reader")

            edited_role = st.selectbox(
                "Role",
                role_options,
                index=role_options.index(current_role)
                if current_role in role_options else 0
            )

            permission_options = ["SELECT", "INSERT", "UPDATE", "DELETE"]

            edited_permissions = st.multiselect(
                "Permissions",
                permission_options,
                default=[
                    p for p in selected_user.get("permissions", [])
                    if p in permission_options
                ]
            )

            save_changes = st.form_submit_button("Save Changes")

            if save_changes:
                clean_username = edited_username.strip()

                duplicate = any(
                    user["username"].lower() == clean_username.lower()
                    and user["username"] != selected_username
                    for user in users
                )

                if not clean_username:
                    st.error("Please enter a username.")

                elif duplicate:
                    st.error("That username is already being used.")

                else:
                    try:
                        update_user(
                            selected_username,
                            clean_username,
                            edited_role,
                            edited_permissions
                        )

                        record_change(
                            "User edited",
                            clean_username,
                            f"Role: {edited_role}; permissions: "
                            f"{', '.join(edited_permissions) if edited_permissions else 'None'}"
                        )

                        st.success("User changes saved.")
                        st.rerun()

                    except Exception as error:
                        st.error(f"Unable to update user: {error}")

        with st.form("delete_user_form"):
            st.warning(f"Delete user '{selected_username}'?")

            delete_submitted = st.form_submit_button("Delete User")

            if delete_submitted:
                try:
                    delete_user(selected_username)

                    record_change(
                        "User deleted",
                        selected_username,
                        "User and associated permissions deleted from PostgreSQL."
                    )

                    st.success(f"User {selected_username} has been deleted.")
                    st.rerun()

                except Exception as error:
                    st.error(f"Unable to delete user: {error}")


# --------------------------------------------------
# CHANGE HISTORY
# --------------------------------------------------

elif page == "Change History":

    st.subheader("Permission Change History")

    try:
        history = get_change_history()

        if not history:
            st.info("No changes have been recorded yet.")

        else:
            history_df = pd.DataFrame(history)

            history_df["time"] = pd.to_datetime(
                history_df["time"]
            ).dt.strftime("%Y-%m-%d %H:%M:%S")

            st.dataframe(
                history_df,
                use_container_width=True,
                hide_index=True
            )

    except Exception as error:
        st.error(f"Unable to load change history: {error}")


# --------------------------------------------------
# ABOUT DBGUARD
# --------------------------------------------------

elif page == "About DBGuard":

    st.subheader("About this project")

    st.write(
        "DBGuard compares database users' actual permissions "
        "against the permissions expected for their assigned roles."
    )

    st.info(
        "This prototype connects to a PostgreSQL database. "
        "It assesses the permission records stored in that database."
    )

    st.subheader("Features")

    st.markdown(
        "- Permission risk assessment\n"
        "- PostgreSQL user management\n"
        "- Permission change history\n"
        "- CSV and PDF security reports"
    )

    st.write("**Developer:** DWCipherLab")
    st.write("**Technology:** Python, Streamlit and PostgreSQL")


st.divider()
st.caption("DBGuard by DWCipherLab • Educational security prototype")
