######   report codes       ######
####################################################################                  report for comments - lionel and jun wen                ###################################################
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    report_c = Report_c_Form()
    if report_c.validate_on_submit():
        form_data = {
            "title": report_c.title.data,
            "remarks": report_c.remarks.data,
        }
        result = store_report_to_mongodb(form_data)
        flash(result)
        return redirect("home")
    return render_template('report_c.html', form=report_c)

def store_report_to_mongodb(form_data):
    # Access the desired collection in the wildvine database
    collection = db["reports_c"]

    # Insert the form data into the collection
    insert_result = collection.insert_one(form_data)
    print("Data inserted with ID:", insert_result.inserted_id)

    return "Report submitted successfully!"



@app.route('/report_c_log')
@admin_login_required
def report_c_log():
    report_data = fetch_report_data_from_mongodb_c()
    return render_template('report_c_log.html', report_data=report_data)



def fetch_report_data_from_mongodb_c():
    collection = db["reports_c"]
    report_data = list(collection.find())  # Retrieve all report documents from the collection
    print("Fetched Report Data:", report_data)  # Add this line for debugging
    return report_data

