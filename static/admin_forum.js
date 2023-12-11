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

function editPost(postId) {
    const newCaption = prompt('Enter new caption:');

    if (newCaption !== null) {
        fetch(`/edit_post/${postId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                caption: newCaption
            })
        })
        .then(response => {
            if (response.ok) {
                // Refresh the page to see the updated post
                window.location.reload(true);
            } else if (response.status === 404) {
                alert('Post not found or unauthorized');
            } else {
                alert('Failed to edit post');
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });
    }
}


function admin_deletePost(postId, csrfToken) {
    if (confirm("Are you sure you want to delete this post?")) {
        // Send an AJAX request to the server to delete the post
        $.ajax({
            url: `/admin_delete_post/${postId}`,
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
                alert("Error deleting the post.");
            }
        });
    }
}


function searchPostsByAuthorId(event) {
        event.preventDefault();

        const searchAuthorId = document.getElementById('search-author-id').value;

        fetch(`/search_posts_by_author?author_id=${searchAuthorId}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            },
        })
        .then(response => response.json())
        .then(data => {
            // Update the posts-container with the new posts data
            const postsContainer = document.getElementById('posts-container');
            postsContainer.innerHTML = data.postsHTML;
        })
        .catch(error => console.error('Error searching posts:', error));
    }


