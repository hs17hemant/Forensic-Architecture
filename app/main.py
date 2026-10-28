from fastapi import FastAPI, HTTPException, Request
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
import datetime

# Configure OTel
trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)
span_processor = BatchSpanProcessor(OTLPSpanExporter())
trace.get_tracer_provider().add_span_processor(span_processor)

app = FastAPI()

@app.post("/login")
async def login(request: Request, user_id: str, success: bool):
    with tracer.start_as_current_span("login_attempt") as span:
        # Canonical Event Mapping
        event = {
            "event_id": f"evt-{int(datetime.datetime.now().timestamp())}",
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "actor_id": user_id,
            "action": "LOGIN",
            "outcome": "SUCCESS" if success else "FAILURE",
            "source_ip": request.client.host,
            "trace_id": format(span.get_span_context().trace_id, "032x")
        }
        span.set_attribute("event_payload", str(event))
        
        if not success:
            raise HTTPException(status_code=401, detail="Authentication failed")
        return {"status": "success", "event": event}
