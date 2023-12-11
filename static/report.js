function toggleReportForm(postId, postCreator) {
        const reportForm = document.getElementById("report-form");
        const reportedPostIdInput = document.getElementById("reported-post-id");
        const reportedPostCreatorInput = document.getElementById("reported-post-creator");

        reportedPostIdInput.value = postId;
        reportedPostCreatorInput.value = postCreator;

        if (reportForm.style.display === "none") {
            reportForm.style.display = "block";
        } else {
            reportForm.style.display = "none";
        }
    }

function submitReport(event) {
    event.preventDefault();

    const reportForm = event.target.closest("form");
    const formData = new FormData(reportForm);

    fetch(reportForm.action, {
        method: "POST",
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert("Report submitted successfully.");
            reportForm.reset();
            reportForm.style.display = "none";
        } else {
            alert("An error occurred while submitting the report.");
        }
    })
    .catch(error => {
        console.error("Error submitting report:", error);
        alert("An error occurred while submitting the report.");
    });
}