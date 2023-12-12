

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


const formPopup = document.querySelector(".form-popup");
const close = document.querySelector(".close");

// Function to show the form popup
function showPopup() {
    formPopup.classList.add("show");
}

// Function to hide the form popup
function hidePopup() {
    formPopup.classList.remove("show");
}

// Call showPopup function when the "LOGIN" button is clicked
document.querySelector(".open-button").addEventListener("click", function () {
    showPopup();
});

// Call hidePopup function when the close button is clicked
close.addEventListener("click", function () {
    hidePopup();
});

// On window load, also trigger the showPopup function after a certain time
window.addEventListener("load", function () {
    setTimeout(function () {
        showPopup();
    }, 5000); // Adjust the time limit as needed
});


