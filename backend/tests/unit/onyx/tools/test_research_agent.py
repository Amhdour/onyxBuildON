from types import SimpleNamespace

from onyx.chat.citation_processor import CitationMode
from onyx.chat.citation_processor import DynamicCitationProcessor
from onyx.chat.models import ChatMessageSimple
from onyx.chat.models import LlmStepResult
from onyx.configs.constants import MessageType
from onyx.server.query_and_chat.placement import Placement
from onyx.server.query_and_chat.streaming_models import AgentResponseStart
from onyx.server.query_and_chat.streaming_models import IntermediateReportCitedDocs
from onyx.tools.fake_tools import research_agent


class _Emitter:
    def __init__(self) -> None:
        self.packets = []

    def emit(self, packet: object) -> None:
        self.packets.append(packet)


class _Generator:
    def __iter__(self):
        return self

    def __next__(self):
        if getattr(self, "_done", False):
            raise StopIteration
        self._done = True
        return SimpleNamespace(obj=AgentResponseStart())


def _fake_pkt_generator(**_: object):
    result = LlmStepResult(answer="intermediate report", tool_calls=[])
    yield from _Generator()
    return (result, False)


def test_generate_intermediate_report_has_no_undefined_context(monkeypatch) -> None:
    monkeypatch.setattr(research_agent, "run_llm_step_pkt_generator", _fake_pkt_generator)

    llm = SimpleNamespace(config=SimpleNamespace(max_input_tokens=4096))
    emitter = _Emitter()
    citation_processor = DynamicCitationProcessor(citation_mode=CitationMode.KEEP_MARKERS)

    report = research_agent.generate_intermediate_report(
        research_topic="topic",
        history=[
            ChatMessageSimple(
                message="hello",
                token_count=1,
                message_type=MessageType.USER,
            )
        ],
        llm=llm,
        token_counter=lambda _: 1,
        citation_processor=citation_processor,
        user_identity=None,
        emitter=emitter,
        placement=Placement(turn_index=0, tab_index=0),
    )

    assert report == "intermediate report"
    assert any(isinstance(packet.obj, IntermediateReportCitedDocs) for packet in emitter.packets)
