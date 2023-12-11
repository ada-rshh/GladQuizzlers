let page = 2;
let isLoading = false;
let loadingDiv;

function loadMorePosts() {
    if (!isLoading) {
        isLoading = true;
        const container = document.getElementById("posts-container");

        fetch(`/get_posts?page=${page}`)
            .then(response => response.text())
            .then(data => {
                if (data.trim() !== "") {
                    container.innerHTML += data;
                    page++;
                }
                isLoading = false;
            });
    }
}

function showLoading() {
    if (!loadingDiv) {
        loadingDiv = document.createElement("div");
        loadingDiv.id = "loading";
        loadingDiv.textContent = "Loading...";
        document.body.appendChild(loadingDiv);
    }
    loadingDiv.style.display = "block";
}

function hideLoading() {
    if (loadingDiv) {
        loadingDiv.style.display = "none";
    }
}

function toggleComments(postId) {
    const commentsList = document.getElementById(`comments-list-${postId}`);
    const commentForm = document.querySelector(`[data-post-id="${postId}"] .comment-form`);
    const commentIcon = document.querySelector(`[data-post-id="${postId}"] .comment-icon`);

    if (commentsList.style.display === 'none') {
        commentsList.style.display = 'block';
        commentIcon.innerHTML = '<i class="fas fa-chevron-up"></i> Hide Comments';
        commentForm.style.display = 'block'; // Show the comment form
    } else {
        commentsList.style.display = 'none';
        commentIcon.innerHTML = '<i class="fas fa-chevron-down"></i> Show Comments';
        commentForm.style.display = 'none'; // Hide the comment form
    }
}

//function getCurrentUserId() {
//    // Use the variable 'username' passed from the Flask template
//    const currentUsername = '{{ username }}';
//    // Return the current user's username or null if the user is not logged in
//    return currentUsername || null;
//}

function addComment(event, postId) {
    event.preventDefault();
    const commentForm = event.target.closest('.comment-form');
    const formData = new FormData(commentForm);
    formData.append('post_id', postId); // Append the postId to the FormData

    fetch(`/add_comment`, {
        method: 'POST',
        body: formData,
    })
    .then(response => response.json())
    .then(data => {
        if ('comment' in data) {
            // Update the comments list with the new comment
            const commentsList = document.getElementById(`comments-list-${postId}`);
            commentsList.innerHTML += `<li>${data.comment}</li>`;

            // Clear the input field after adding the comment
            commentForm.reset();
        } else {
            console.error('Error: Comment not added');
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
}


function toggleDropdown(postId) {
    var dropdown = document.getElementById('dropdown-' + postId);
    dropdown.classList.toggle('show');
}

function toggleEditForm(postId) {
    const editForm = document.getElementById('edit-form-' + postId);
    editForm.style.display = editForm.style.display === 'none' ? 'block' : 'none';
}

function editPost(postId, csrfToken) {
    const newCaption = prompt('Enter new caption:');

    if (newCaption !== null) {
        fetch(`/edit_post/${postId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken  // Include the CSRF token
            },
            body: JSON.stringify({
                caption: newCaption
            })
        })
        .then(response => {
            if (response.ok) {
                // Refresh the page to see the updated post
                window.location.reload(true);
            } else {
                console.error(response.statusText);
                displayAlert("Error in editing post!");
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }
}



function displayAlert(message) {
    const alertElement = document.createElement('div');
    alertElement.classList.add('alert');
    alertElement.textContent = message;

    // Add the alert to the top of the page
    const forumContainer = document.getElementById('posts-container');
    forumContainer.insertBefore(alertElement, forumContainer.firstChild);

    // Remove the alert after a few seconds (adjust the delay as needed)
    setTimeout(() => {
        forumContainer.removeChild(alertElement);
    }, 5000); // Display for 5 seconds
}

//function deletePost(postId) {
//    if (confirm("Are you sure you want to delete this post?")) {
//        fetch(`/delete_post/${postId}`, {
//            method: 'DELETE',
//        })
//        .then(response => {
//            if (response.ok) {
//                return response.json();
//            } else if (response.status === 401) {
//                return response.json().then(data => Promise.reject(data.error));
//            } else {
//                return Promise.reject('Failed to delete post');
//            }
//        })
//        .then(data => {
//            // Show an alert to indicate successful deletion
//            alert(data.message);
//            // Redirect to the forum page after successful deletion without adding to history
//            window.location.replace('/forum');
//        })
//        .catch(error => {
//            console.error('Error:', error);
//            // If there's an error, show an alert with the error message
//            alert(error);
//            // Refresh the page on error (even for unauthorized users)
//            window.location.reload(true); // Use true to force a hard refresh
//        });
//    } else {
//        // If the user clicks "Cancel", simply refresh the page
//        window.location.reload(true); // Use true to force a hard refresh
//    }
//}

function deletePost(postId, csrfToken) {
    if (confirm("Are you sure you want to delete this post?")) {
        // Send an AJAX request to the server to delete the post
        $.ajax({
            url: `/delete_post/${postId}`,
            type: 'POST',
            data: {
                csrf_token: csrfToken  // Include the CSRF token in the data
            },
            success: function(response) {
                // Handle success
                alert(response.message);
                location.reload();  // Reload the page after successful deletion
            },
            error: function(xhr, status, error) {
                // Handle error
                console.error(error);
                alert("You are not authorized to delete this post!.");
            }
        });
    }
}


//function admin_deletePost(postId, csrfToken) {
//    if (confirm("Are you sure you want to delete this post?")) {
//        // Send an AJAX request to the server to delete the post
//        $.ajax({
//            url: `/admin_delete_post/${postId}`,
//            type: 'POST',
//            data: {
//                csrf_token: csrfToken  // Include the CSRF token in the data
//            },
//            success: function(response) {
//                // Handle success
//                alert(response.message);
//                location.reload();  // Reload the page after successful deletion
//            },
//            error: function(xhr, status, error) {
//                // Handle error
//                console.error(error);
//                alert("Error deleting the post.");
//            }
//        });
//    }
//}


