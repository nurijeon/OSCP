[JavaScript Runtime](#JavaScript-Runtime)
[Debounce/Throttling](#Debounce/Throttling)
[This Binding](#this-binding)
[Promisify](#promisify)
[JavaScript Types](#JavaScript-Types)

# JavaScript Runtime

- JavaScript runtime: Where your javascript code is executed when you run it. 
  - Google Chrome: v8
  - Mozilla - Spidermonkey
  - IE - Chakra
  - Node: v8
  - Single threaded (one thing at a time)
 
- Call Stack
  - Data structure which records where in the program we are
  - If we step into a function, we put something on to the stack
  - If we return from a function, we pop off the top of the stack
 ![image](https://github.com/nuricheun/OSCP/assets/14031269/ce76659a-d2b3-4e03-ba21-2ec8c1b34f4d)

- Concurrency & Event Loop: prevents browser from getting blocked
  - Web Browser is more than just a runtime
  - It can do more than one thing at a time because it has WebAPIs(On the backend it's C++ APIs)
  ex) setTimeout:
  - When Call Stack hit webapis, it will send it to WebaAPIs and pop it off of the stack
  - When WebAPIs is done processing the function, it will send the callback to task queue(or callback queue)
  - Event loop will look at the stack, wait until it's clear and if it's empty it will send the callback back onto the stack

- WebAPIs
  - Web browser
 
- Callback Queue(Task queue)


- Callback function
  - It can be any function that another function calls
  - Or it can be asynchronous callback as in one that it's going to be pushed back on the Callback Queue in the future

- Render Queue
  - Your browser is rerendering brwoser every 16.60 milli seconds
  - It's queue onto Render Queue
  - It has to wait until the stack is clear
  - It's higher priority than callback queue
  - So if your callstack is blocked with synchronous work, render has to wait
  - But if we use asynchromous work, then we give browser a chance to render every once in a while
  - This is why we shouldn't put shitty slow code to block call stack because it will block browser from rendering!!!

 
- setTimeout
  - minimum time to execution
 
# Debounce/Throttling

- Higher order function: function that returns another function
- We need to wait until the delay miliseconds have passwed and call callback function: setTimeout
- If we call the function again before the delay is up, we reset the delay: clearTimeout
- We need to have the same timerID so we have to save timerID between function calls: use closer
- We need a way to pass arguments to the callback function but we don't know how many arguments we're getting: use rest parameter ...args
- We need a way to bind callback with the correct "this" context: callback.apply(this, args)
- We shouldn't use arrow function

```bash
function debounce(callback, delay, immediate = false) {
  // Write your code here.
  let timeID = null;
  
  return function(...args){
    clearTimeout(timeID);
    
    if(immediate && timeID == null){
      callback.apply(this, args);
    }

    timeID = setTimeout(() => {
      if(!immediate){
        callback.apply(this, args);
      }
      timeID = null;
    }, delay)
  }
}
```

# This Binding
- symbol is unique
- symbol is also non-enumerable

```bash
Function.prototype.myCall = function (thisContext, ...args) {
  // Write your code here.
  const sym = Symbol();

  thisContext[sym] = this;
  let res = thisContext[sym](...args)
  delete thisContext[sym]
  return res;
};

Function.prototype.myApply = function (thisContext, args = []) {
  // Write your code here.
  const sym = Symbol();

  thisContext[sym] = this;
  let res = thisContext[sym](...args)
  delete thisContext[sym]
  return res;
};

Function.prototype.myBind = function (thisContext, ...args) {
   return (...newArgs) => this.myApply(thisContext, [...args, ...newArgs])
};
```

# Promisify
```bash
function promisify(callback) {
  // Write your code here.
  return function(...args){
    return new Promise((resolve, reject) => {
      function handleErrorAndValue(error, value){
        if(error){
          reject(error)
        }else{
          resolve(value)
        }
      }
      callback.apply(this, [...args, handleErrorAndValue)
    })
  }
}
```



# JavaScript Types
**object**
```bash
typeof obj === 'object' && obj !== null
```

**array**
```bash
Array.isArray(obj)
```

