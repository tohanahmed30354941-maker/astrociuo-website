const express = require("express");
const app = express();

app.use(express.json());
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.send("Astrociuo Website is Online!");
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Astrociuo running on port ${PORT}`);
});
