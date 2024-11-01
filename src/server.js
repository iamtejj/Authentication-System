import app from "./app.js";
import config from "./config/config.js";
import databaseService from "./service/databaseService.js";


const server = app.listen(config.PORT);
(async () => {
    try {
        // Database Connection
        const connection = await databaseService.connect();
        console.log("database connected successfully");
        
    } catch (err) {

        server.close((error) => {
            if (error) {
                console.log(error)
            }

            process.exit(1)
        });
    }
})();