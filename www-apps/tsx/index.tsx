const path = process.env.PATH_INFO || "/";
const method = process.env.REQUEST_METHOD || "GET";
console.log(`hello from tsx path=${path} method=${method}`);
