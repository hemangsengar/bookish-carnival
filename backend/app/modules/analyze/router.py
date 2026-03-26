from fastapi import APIRouter, Depends, File, Form, UploadFile

from app.modules.analyze.dependencies import get_analyze_service
from app.modules.analyze.file_extract import extract_text_from_file
from app.modules.analyze.schemas import AnalyzeOptions, AnalyzeRequest, AnalyzeResponse
from app.modules.analyze.service import AnalyzeService

router = APIRouter(tags=["analyze"])


@router.post("/analyze", response_model=AnalyzeResponse, summary="Analyze text/log/sql/chat payload")
def analyze_payload(
    request: AnalyzeRequest,
    service: AnalyzeService = Depends(get_analyze_service),
) -> AnalyzeResponse:
    return service.analyze(input_type=request.input_type, content=request.content, options=request.options)


@router.post("/analyze/file", response_model=AnalyzeResponse, summary="Analyze uploaded file")
async def analyze_file(
    file: UploadFile = File(...),
    input_type: str = Form(default="log"),
    mask: bool = Form(default=True),
    block_high_risk: bool = Form(default=True),
    log_analysis: bool = Form(default=True),
    service: AnalyzeService = Depends(get_analyze_service),
) -> AnalyzeResponse:
    file_bytes = await file.read()
    content = extract_text_from_file(filename=file.filename or "upload.txt", file_bytes=file_bytes)
    options = AnalyzeOptions(mask=mask, block_high_risk=block_high_risk, log_analysis=log_analysis)
    return service.analyze(input_type=input_type, content=content, options=options)
