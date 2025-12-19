"""Judge natural language answers using Claude via claude-agent-sdk."""

import anyio
from dataclasses import dataclass
from enum import Enum
from typing import AsyncIterator

from claude_agent_sdk import query, ClaudeAgentOptions, AssistantMessage, TextBlock

from .questions import Question


class Verdict(Enum):
    """Verdict for an answer."""
    CORRECT = "correct"
    PARTIAL = "partial"
    INCORRECT = "incorrect"


@dataclass
class JudgmentResult:
    """Result of judging an answer."""
    verdict: Verdict
    score: int  # 0-100
    feedback: str
    correct_answer: str | None  # Only if incorrect
    key_points_hit: list[str]
    key_points_missed: list[str]


JUDGE_SYSTEM_PROMPT = """You are a Kubernetes expert evaluating quiz answers. Your job is to:

1. Evaluate if the answer demonstrates understanding of the concept
2. Be lenient with terminology and phrasing - focus on concepts, not exact words
3. Give partial credit for partially correct answers
4. Provide constructive feedback

IMPORTANT EVALUATION GUIDELINES:
- CORRECT: The answer covers the main concepts correctly. Minor omissions are OK.
- PARTIAL: The answer shows some understanding but misses important points.
- INCORRECT: The answer is fundamentally wrong or completely misses the point.

Be encouraging but accurate. If they're close, tell them what they got right before explaining what's missing."""


def build_judge_prompt(question: Question, user_answer: str) -> str:
    """Build the prompt for the judge."""
    return f"""## Question
{question.question}

## Relevant Kubernetes Manifests
```yaml
{question.context[:3000]}  # Truncate if too long
```

## Key Concepts the Answer Should Cover
{chr(10).join(f"- {concept}" for concept in question.key_concepts)}

## User's Answer
{user_answer}

## Your Task
Evaluate this answer and respond in EXACTLY this format:

VERDICT: [CORRECT|PARTIAL|INCORRECT]
SCORE: [0-100]

FEEDBACK:
[Your constructive feedback here - 2-4 sentences]

KEY_POINTS_HIT:
[List concepts they got right, one per line, or "None" if none]

KEY_POINTS_MISSED:
[List concepts they missed, one per line, or "None" if all covered]

CORRECT_ANSWER:
[Only if INCORRECT - provide a brief correct answer. Otherwise write "N/A"]
"""


async def judge_answer_async(question: Question, user_answer: str) -> JudgmentResult:
    """Judge an answer using Claude asynchronously."""

    prompt = build_judge_prompt(question, user_answer)

    options = ClaudeAgentOptions(
        system_prompt=JUDGE_SYSTEM_PROMPT,
        max_turns=1,
    )

    response_text = ""

    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    response_text += block.text

    return parse_judgment(response_text)


def judge_answer(question: Question, user_answer: str) -> JudgmentResult:
    """Judge an answer using Claude (synchronous wrapper)."""
    return anyio.run(judge_answer_async, question, user_answer)


def parse_judgment(response: str) -> JudgmentResult:
    """Parse Claude's judgment response."""
    lines = response.strip().split('\n')

    verdict = Verdict.PARTIAL  # Default
    score = 50
    feedback = ""
    correct_answer = None
    key_points_hit = []
    key_points_missed = []

    current_section = None

    for line in lines:
        line = line.strip()

        if line.startswith('VERDICT:'):
            verdict_str = line.replace('VERDICT:', '').strip().upper()
            if 'CORRECT' in verdict_str and 'INCORRECT' not in verdict_str:
                verdict = Verdict.CORRECT
            elif 'INCORRECT' in verdict_str:
                verdict = Verdict.INCORRECT
            else:
                verdict = Verdict.PARTIAL

        elif line.startswith('SCORE:'):
            try:
                score = int(line.replace('SCORE:', '').strip().split()[0])
                score = max(0, min(100, score))  # Clamp to 0-100
            except (ValueError, IndexError):
                pass

        elif line.startswith('FEEDBACK:'):
            current_section = 'feedback'
            feedback = line.replace('FEEDBACK:', '').strip()

        elif line.startswith('KEY_POINTS_HIT:'):
            current_section = 'hit'

        elif line.startswith('KEY_POINTS_MISSED:'):
            current_section = 'missed'

        elif line.startswith('CORRECT_ANSWER:'):
            current_section = 'correct'
            answer_part = line.replace('CORRECT_ANSWER:', '').strip()
            if answer_part and answer_part.upper() != 'N/A':
                correct_answer = answer_part

        elif line.startswith('- ') or line.startswith('* '):
            point = line[2:].strip()
            if point.lower() != 'none':
                if current_section == 'hit':
                    key_points_hit.append(point)
                elif current_section == 'missed':
                    key_points_missed.append(point)

        elif current_section == 'feedback' and line:
            feedback += ' ' + line

        elif current_section == 'correct' and line and line.upper() != 'N/A':
            if correct_answer:
                correct_answer += ' ' + line
            else:
                correct_answer = line

    return JudgmentResult(
        verdict=verdict,
        score=score,
        feedback=feedback.strip(),
        correct_answer=correct_answer,
        key_points_hit=key_points_hit,
        key_points_missed=key_points_missed,
    )


# Fallback for when Claude is not available
def judge_answer_offline(question: Question, user_answer: str) -> JudgmentResult:
    """Simple keyword-based judging as fallback."""
    user_lower = user_answer.lower()
    hits = []
    misses = []

    for concept in question.key_concepts:
        # Simple keyword matching
        keywords = concept.lower().split()
        if any(kw in user_lower for kw in keywords if len(kw) > 3):
            hits.append(concept)
        else:
            misses.append(concept)

    if not misses:
        verdict = Verdict.CORRECT
        score = 100
    elif len(hits) >= len(misses):
        verdict = Verdict.PARTIAL
        score = int(100 * len(hits) / len(question.key_concepts))
    else:
        verdict = Verdict.INCORRECT
        score = int(100 * len(hits) / len(question.key_concepts))

    return JudgmentResult(
        verdict=verdict,
        score=score,
        feedback=f"Matched {len(hits)} of {len(question.key_concepts)} key concepts.",
        correct_answer=None if verdict != Verdict.INCORRECT else "; ".join(question.key_concepts),
        key_points_hit=hits,
        key_points_missed=misses,
    )
