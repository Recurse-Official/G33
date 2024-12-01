import "./App.css";
import Homepage from "./Pages/Homepage";
import { Route } from "react-router-dom";
import Chatpage from "./Pages/Chatpage";
import React, {  useEffect } from "react";

function App() {
  // const [darkMode, setDarkMode] = useState(false);

  // Check localStorage for user's theme preference
  useEffect(() => {
    const savedTheme = localStorage.getItem("theme");
    if (savedTheme === "dark") {
      // setDarkMode(true);
      document.body.classList.add("dark-mode");
    }
  }, []);

  // Handle dark mode toggle
  // const toggleDarkMode = () => {
  //   setDarkMode(!darkMode);
  //   if (!darkMode) {
  //     document.body.classList.add("dark-mode");
  //     localStorage.setItem("theme", "dark");
  //   } else {
  //     document.body.classList.remove("dark-mode");
  //     localStorage.setItem("theme", "light");
  //   }
  // };

  return (
    <div className="App">
      {/* Dark Mode Toggle Button */}
      {/* <div className="dark-mode-toggle">
        <button onClick={toggleDarkMode}>
          {darkMode ? "Light Mode" : "Dark Mode"}
        </button>
      </div> */}

      {/* Routing */}
      <Route path="/" component={Homepage} exact />
      <Route path="/chats" component={Chatpage} />
    </div>
  );
}

export default App;
