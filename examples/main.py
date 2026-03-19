from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
import uvicorn

async def hello_endpoint(request):
    return JSONResponse({"message": "Hello Wireguard"})

routes = [
    Route("/", hello_endpoint, methods=["GET"]),
]

app = Starlette(routes=routes)

if __name__ == "__main__":
    uvicorn.run(app, host="10.124.16.2", port=8000)