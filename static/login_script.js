

//  const loginPopup = document.querySelector(".login-popup");
//  const close = document.querySelector(".close");
//
//
//  window.addEventListener("load",function(){
//
//   showPopup();
//   // setTimeout(function(){
//   //   loginPopup.classList.add("show");
//   // },5000)
//
//  })
//
//  function showPopup(){
//        const timeLimit = 5 // seconds;
//        let i=0;
//        const timer = setInterval(function(){
//         i++;
//         if(i == timeLimit){
//          clearInterval(timer);
//          loginPopup.classList.add("show");
//         }
//         console.log(i)
//        },1000);
//  }
//
//
//  close.addEventListener("click",function(){
//    loginPopup.classList.remove("show");
//  })


//const formPopup = document.querySelector(".form-popup");
//const close = document.querySelector(".close");
//
//window.addEventListener("load", function () {
//    showPopup();
//});
//
//function showPopup() {
//    const timeLimit = 5; // seconds
//    let i = 0;
//    const timer = setInterval(function () {
//        i++;
//        if (i === timeLimit) {
//            clearInterval(timer);
//            formPopup.classList.add("show");
//        }
//    }, 1000);
//}
//
//close.addEventListener("click", function () {
//    formPopup.classList.remove("show");
//});


// const formPopup = document.querySelector(".form-popup");
// const close = document.querySelector(".close");

// // Function to show the form popup
// function showPopup() {
//     formPopup.classList.add("show");
// }

// // Function to hide the form popup
// function hidePopup() {
//     formPopup.classList.remove("show");
// }

// // Call showPopup function when the "LOGIN" button is clicked
// document.querySelector(".open-button").addEventListener("click", function () {
//     showPopup();
// });

// // Call hidePopup function when the close button is clicked
// close.addEventListener("click", function () {
//     hidePopup();
// });

// // On window load, also trigger the showPopup function after a certain time
// window.addEventListener("load", function () {
//     setTimeout(function () {
//         showPopup();
//     }, 5000); // Adjust the time limit as needed
// });



const formPopup = document.querySelector(".form-popup");
const close = document.querySelector(".close");

// Function to show the form popup
function showPopup(formId) {
    document.getElementById(formId).classList.add("show");
}

// Function to hide the form popup
function hidePopup(formId) {
    const formElement = document.getElementById(formId);

    if (!formElement) {
        console.error(`Element with ID '${formId}' not found`);
        return;
    }

    formElement.classList.remove("show");
}


// Call showPopup function when the "LOGIN" button is clicked
document.querySelector(".open-login").addEventListener("click", function () {
    showPopup('loginForm');
});

// Call showPopup function when the "SIGN UP" button is clicked
document.querySelector(".open-signup").addEventListener("click", function () {
    showPopup('signupForm');
});

document.querySelector(".open-teacherlogin").addEventListener("click", function () {
    showPopup('teacherloginForm');
});

document.querySelector(".open-teachersignup").addEventListener("click", function () {
    showPopup('teachersignupForm');
});

// Call hidePopup function when the close button is clicked
close.addEventListener("click", function () {
    hidePopup('loginForm'); // Update with the correct form ID
    hidePopup('signupForm'); // Update with the correct form ID
    hidePopup('teacherloginForm'); // Update with the correct form ID
    hidePopup('teachersignupForm'); // Update with the correct form ID
});