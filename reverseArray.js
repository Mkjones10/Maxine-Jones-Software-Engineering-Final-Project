// Function to print array
function printArray(arr) {
    console.log("Reversed array is:-");
    console.log(arr.join(" "));
  }
  
  // Function to reverse array using recursion
  function reverseArray(arr, start, end) {
    if (start < end) {
      //swap elements
      [arr[start], arr[end]] = [arr[end], arr[start]];
      reverseArray(arr, start + 1, end - 1);
      console.log(arr[start],+" "+ arr[end])
      
    }
  }
  
  let arr = [5, 4, 3, 2, 1];
  console.log(arr)
  reverseArray(arr, 0, arr.length - 1);
  printArray(arr);