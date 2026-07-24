"""
examples/fastapi_demo.py
~~~~~~~~~~~~~~~~~~~~~~~~~
Example demonstrating zero-code-rewrite FastAPI integration with AI SOS.
"""

from fastapi import FastAPI
import uvicorn
import aisos

app = FastAPI(title="AI SOS Protected FastAPI Service")

# Initialize AI SOS and attach to FastAPI app instance
security = aisos.init()
security.attach(app)


@app.get("/api/v1/health")
def health():
    return {"status": "healthy", "security": "AI SOS Active"}


@app.get("/api/v1/search")
def search(q: str = ""):
    # Query parameter q will be automatically observed and scanned by AI SOS
    return {"status": "success", "query": q}


@app.get("/api/v1/leak-test")
def leak_test():
    # If a endpoint leaks a key, AI SOS outbound response layer intercepts it automatically
    return {"config": "sk-1234567890abcdef1234567890abcdef"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
