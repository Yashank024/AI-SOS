"""
examples/openai_demo.py
~~~~~~~~~~~~~~~~~~~~~~~~
Example demonstrating passive OpenAI SDK instrumentation with AI SOS.
"""

import aisos
import openai

# Initialize AI SOS and passively patch the OpenAI SDK
security = aisos.init()
security.attach("openai")

# Outgoing chat completion calls are now automatically observed and protected
client = openai.OpenAI(api_key="sk-dummy-key-for-testing")

print("[AI SOS] OpenAI SDK passively attached. Sending completion request...")

try:
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Hello, world!"}
        ]
    )
    print("Response:", response)
except Exception as e:
    print("Execution completed:", e)
