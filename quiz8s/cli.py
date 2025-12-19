"""Command-line interface for the Kubernetes quiz."""

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.markdown import Markdown
from rich import box

from .parser import scan_manifests, ClusterArchitecture
from .questions import QuestionGenerator, QuestionCategory, Question
from .judge import judge_answer, judge_answer_offline, Verdict, JudgmentResult
from .generator import generate_questions

console = Console()


def display_welcome():
    """Display welcome message."""
    console.print(Panel.fit(
        "[bold blue]Quiz8s[/bold blue] - Kubernetes GitOps Quiz\n\n"
        "Test your understanding of how Kubernetes deployments work together.\n"
        "Answer questions in natural language - Claude will judge your responses.",
        title="Welcome",
        border_style="blue"
    ))


def display_categories(generator: QuestionGenerator) -> dict[str, QuestionCategory]:
    """Display available categories and return mapping."""
    table = Table(title="Question Categories", box=box.ROUNDED)
    table.add_column("#", style="cyan", width=3)
    table.add_column("Category", style="green")
    table.add_column("Questions", style="yellow", justify="right")

    categories = {}
    for i, cat in enumerate(QuestionCategory, 1):
        questions = generator.get_questions(category=cat)
        if questions:
            categories[str(i)] = cat
            table.add_row(str(i), cat.value, str(len(questions)))

    # Add "all" option
    all_count = len(generator.get_questions())
    table.add_row("A", "All Categories", str(all_count))
    categories['a'] = None

    console.print(table)
    return categories


def display_question(question: Question, number: int, total: int):
    """Display a question."""
    console.print()
    console.print(Panel(
        f"[bold]{question.question}[/bold]",
        title=f"[cyan]Question {number}/{total}[/cyan] | "
              f"[yellow]{question.category.value}[/yellow] | "
              f"[magenta]{question.difficulty.title()}[/magenta]",
        border_style="cyan"
    ))

    # Show hints option
    console.print("\n[dim]Type 'hint' for hints, 'context' to see the manifest, "
                  "'skip' to skip, or 'quit' to exit.[/dim]\n")


def display_context(question: Question):
    """Display the manifest context for a question."""
    console.print(Panel(
        Markdown(f"```yaml\n{question.context}\n```"),
        title="Relevant Manifest",
        border_style="dim"
    ))


def display_hints(question: Question):
    """Display hints for a question."""
    hints_text = "\n".join(f"  - {hint}" for hint in question.hints)
    console.print(Panel(
        f"[yellow]{hints_text}[/yellow]",
        title="Hints",
        border_style="yellow"
    ))


def display_judgment(result: JudgmentResult):
    """Display the judgment result."""
    # Verdict color
    if result.verdict == Verdict.CORRECT:
        verdict_style = "bold green"
        verdict_emoji = "[green]✓[/green]"
    elif result.verdict == Verdict.PARTIAL:
        verdict_style = "bold yellow"
        verdict_emoji = "[yellow]~[/yellow]"
    else:
        verdict_style = "bold red"
        verdict_emoji = "[red]✗[/red]"

    console.print()
    console.print(Panel(
        f"{verdict_emoji} [{verdict_style}]{result.verdict.value.upper()}[/{verdict_style}] "
        f"- Score: [bold]{result.score}/100[/bold]\n\n"
        f"[white]{result.feedback}[/white]",
        title="Judgment",
        border_style="cyan"
    ))

    # Key points
    if result.key_points_hit:
        console.print("\n[green]What you got right:[/green]")
        for point in result.key_points_hit:
            console.print(f"  [green]✓[/green] {point}")

    if result.key_points_missed:
        console.print("\n[yellow]What you missed:[/yellow]")
        for point in result.key_points_missed:
            console.print(f"  [yellow]○[/yellow] {point}")

    if result.correct_answer:
        console.print(Panel(
            result.correct_answer,
            title="[red]Correct Answer[/red]",
            border_style="red"
        ))


def display_final_score(correct: int, partial: int, incorrect: int, total: int):
    """Display final score."""
    score = (correct * 100 + partial * 50) / max(total, 1)

    table = Table(title="Quiz Complete!", box=box.DOUBLE)
    table.add_column("Result", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("[green]Correct[/green]", str(correct))
    table.add_row("[yellow]Partial[/yellow]", str(partial))
    table.add_row("[red]Incorrect[/red]", str(incorrect))
    table.add_row("[dim]Skipped[/dim]", str(total - correct - partial - incorrect))
    table.add_row("", "")
    table.add_row("[bold]Final Score[/bold]", f"[bold]{score:.0f}%[/bold]")

    console.print()
    console.print(table)


def run_quiz(generator: QuestionGenerator, questions: list[Question], use_claude: bool = True):
    """Run the quiz loop."""
    correct = 0
    partial = 0
    incorrect = 0
    answered = 0

    for i, question in enumerate(questions, 1):
        display_question(question, i, len(questions))

        while True:
            answer = Prompt.ask("[bold cyan]Your answer[/bold cyan]")

            if answer.lower() == 'quit':
                if Confirm.ask("Are you sure you want to quit?"):
                    display_final_score(correct, partial, incorrect, answered)
                    return
                continue

            if answer.lower() == 'skip':
                console.print("[dim]Skipped[/dim]")
                break

            if answer.lower() == 'hint':
                display_hints(question)
                continue

            if answer.lower() == 'context':
                display_context(question)
                continue

            if len(answer.strip()) < 10:
                console.print("[red]Please provide a more detailed answer (at least 10 characters).[/red]")
                continue

            # Judge the answer
            with console.status("[bold cyan]Claude is evaluating your answer...[/bold cyan]"):
                try:
                    if use_claude:
                        result = judge_answer(question, answer)
                    else:
                        result = judge_answer_offline(question, answer)
                except Exception as e:
                    console.print(f"[yellow]Claude unavailable, using offline judging: {e}[/yellow]")
                    result = judge_answer_offline(question, answer)

            display_judgment(result)
            answered += 1

            if result.verdict == Verdict.CORRECT:
                correct += 1
            elif result.verdict == Verdict.PARTIAL:
                partial += 1
            else:
                incorrect += 1

            break

        # Continue prompt
        if i < len(questions):
            if not Confirm.ask("\nContinue to next question?", default=True):
                break

    display_final_score(correct, partial, incorrect, answered)


def list_questions(generator: QuestionGenerator, category: QuestionCategory = None):
    """List all available questions."""
    questions = generator.get_questions(category=category)

    table = Table(title=f"Available Questions ({len(questions)} total)", box=box.ROUNDED)
    table.add_column("#", style="cyan", width=3)
    table.add_column("Category", style="green", width=20)
    table.add_column("Difficulty", style="magenta", width=10)
    table.add_column("Question", style="white", no_wrap=False)

    for i, q in enumerate(questions, 1):
        # Truncate long questions
        q_text = q.question[:80] + "..." if len(q.question) > 80 else q.question
        table.add_row(str(i), q.category.value, q.difficulty.title(), q_text)

    console.print(table)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Quiz8s - Test your Kubernetes GitOps knowledge"
    )
    parser.add_argument(
        "manifest_dir",
        nargs="?",
        default="./Asimov-k8s",
        help="Directory containing Kubernetes manifests (default: ./Asimov-k8s)"
    )
    parser.add_argument(
        "-n", "--num-questions",
        type=int,
        default=5,
        help="Number of questions per quiz (default: 5)"
    )
    parser.add_argument(
        "-d", "--difficulty",
        choices=["easy", "medium", "hard"],
        help="Filter by difficulty"
    )
    parser.add_argument(
        "-l", "--list",
        action="store_true",
        help="List all available questions without starting quiz"
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Use offline keyword-based judging (no Claude)"
    )
    parser.add_argument(
        "-g", "--generate",
        action="store_true",
        help="Generate fresh questions using Claude (instead of using pre-built questions)"
    )
    parser.add_argument(
        "-f", "--focus",
        type=str,
        help="Focus area for generated questions (e.g., 'TLS', 'Flux', 'Ingress', 'Secrets')"
    )

    args = parser.parse_args()

    # Check manifest directory
    manifest_path = Path(args.manifest_dir)
    if not manifest_path.exists():
        console.print(f"[red]Error: Directory not found: {manifest_path}[/red]")
        sys.exit(1)

    # Parse manifests
    with console.status("[bold blue]Parsing Kubernetes manifests...[/bold blue]"):
        arch = scan_manifests(manifest_path)
        generator = QuestionGenerator(arch)

    console.print(f"[green]Found {len(arch.resources)} resources in {manifest_path}[/green]")

    # List mode
    if args.list:
        list_questions(generator)
        return

    # Interactive mode
    display_welcome()

    # Dynamic generation mode
    if args.generate:
        focus_msg = f" focused on [yellow]{args.focus}[/yellow]" if args.focus else ""
        console.print(f"\n[cyan]Generating {args.num_questions} fresh questions{focus_msg}...[/cyan]")

        with console.status("[bold blue]Claude is analyzing your manifests and creating questions...[/bold blue]"):
            try:
                questions = generate_questions(
                    arch,
                    count=args.num_questions,
                    focus_area=args.focus,
                    difficulty=args.difficulty
                )
            except Exception as e:
                console.print(f"[red]Error generating questions: {e}[/red]")
                console.print("[yellow]Falling back to pre-built questions...[/yellow]")
                questions = generator.get_questions(
                    difficulty=args.difficulty,
                    count=args.num_questions
                )

        if not questions:
            console.print("[red]Failed to generate questions. Try again or use pre-built questions.[/red]")
            sys.exit(1)

        console.print(f"[green]Generated {len(questions)} questions![/green]")
    else:
        # Pre-built questions mode
        console.print()
        categories = display_categories(generator)

        choice = Prompt.ask(
            "\nSelect a category",
            choices=list(categories.keys()),
            default="a"
        )

        selected_category = categories.get(choice.lower())

        # Get questions
        questions = generator.get_questions(
            category=selected_category,
            difficulty=args.difficulty,
            count=args.num_questions
        )

        if not questions:
            console.print("[red]No questions available for the selected criteria.[/red]")
            sys.exit(1)

    console.print(f"\n[green]Starting quiz with {len(questions)} questions...[/green]")

    # Run quiz
    run_quiz(generator, questions, use_claude=not args.offline)


if __name__ == "__main__":
    main()
