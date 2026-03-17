"""A well-structured module demonstrating clean Python code."""

import math
from typing import Optional


def calculate_area(radius: float) -> float:
    """Calculate the area of a circle given its radius."""
    if radius < 0:
        raise ValueError("Radius cannot be negative")
    return math.pi * radius ** 2


def fibonacci(n: int) -> list[int]:
    """Return the first n Fibonacci numbers."""
    if n <= 0:
        return []
    if n == 1:
        return [0]

    sequence = [0, 1]
    for _ in range(2, n):
        sequence.append(sequence[-1] + sequence[-2])
    return sequence


class Shape:
    """Base class for geometric shapes."""

    def __init__(self, name: str) -> None:
        """Initialize shape with a name."""
        self.name = name

    def area(self) -> float:
        """Calculate the area of the shape."""
        raise NotImplementedError

    def describe(self) -> str:
        """Return a human-readable description."""
        return f"{self.name} with area {self.area():.2f}"
