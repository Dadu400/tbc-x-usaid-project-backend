const app = require('./app');

const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => res.send("Express on Vercel1"));

app.listen(2999, () => {
    console.log(`Server is running on port ${PORT}`);
});


module.exports = app;