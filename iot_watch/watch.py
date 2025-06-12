import pygame
import sys

import sqlite3
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import matplotlib
import io
import numpy as np


# Use Agg backend (for headless rendering)
matplotlib.use("Agg")

# --- SQLite Setup ---
conn = sqlite3.connect("steps.db")
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS steps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        step INTEGER NOT NULL,
        timestamp TEXT NOT NULL
    )
''')
conn.commit()

# Initialize Pygame
pygame.init()

# Set up the display
screen_width = 800
screen_height = 600
screen = pygame.display.set_mode((screen_width, screen_height))
pygame.display.set_caption("Watch App")

clock = pygame.time.Clock()

# Font settings
font = pygame.font.SysFont(None, 48)  # (font name, size)

# Load the image (make sure the file path is correct)
image = pygame.image.load("background.jpg")  # Replace with your image file

user_id = "user123"  # Can be dynamically set in a real app
steps = 0

def generate_time_bins(hours=24, interval_minutes=10):
    """
    Generate a list of (start_time, end_time) tuples for time bins over the last `hours`.

    Args:
        hours (int): Number of hours to go back from now (default: 24)
        interval_minutes (int): Duration of each time bin in minutes (default: 10)

    Returns:
        List[Tuple[datetime, datetime]]: List of time bin ranges
    """
    now = datetime.now()
    start_time = now - timedelta(hours=hours)
    bins = []

    # Calculate the number of bins
    total_intervals = (hours * 60) // interval_minutes

    for i in range(total_intervals):
        bin_start = start_time + timedelta(minutes=i * interval_minutes)
        bin_end = bin_start + timedelta(minutes=interval_minutes)
        bins.append((bin_start, bin_end))

    return bins

def get_step_data():
    """Fetch steps from the last 24 hours, grouped into 10-minute intervals."""

    results = {}
    bins = generate_time_bins(hours=24, interval_minutes=10)
    for start, end in bins:
        print(f"{start} --> {end}")
        cursor.execute(
            "SELECT count(timestamp) as `count` FROM steps WHERE user_id = ? AND timestamp >= ? AND timestamp < ?",
            (user_id, start, end)
        )
        rows = cursor.fetchall()
        for row in rows:
            results[start] = row[0]

    times = results.keys()
    values = [results.get(t, 0) for t in times]
    # Create sorted time series
    #times = [start_time + timedelta(minutes=10 * i) for i in range(144)]  # 144 bins in 24 hrs
    #values = [bins.get(t, 0) for t in times]

    return times, values



def draw_step_graph():
    """Generate and return a Pygame image surface of the graph."""
    times, values = get_step_data()
    print(f"Step Data: {times}, {values}")

    # Create plot
    fig, ax = plt.subplots(figsize=(6, 2))
    ax.plot(times, values, color='blue')
    ax.set_title("Steps per 10 Minutes (Last 24h)")
    ax.set_xlabel("Time")
    ax.set_ylabel("Steps")
    fig.autofmt_xdate()

    # Save plot to a surface
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close(fig)

    # Convert to Pygame surface
    graph_image = pygame.image.load(buf, 'graph.png').convert()
    buf.close()
    return graph_image

graph_surface = draw_step_graph()
graph_last_updated = pygame.time.get_ticks()

# Main loop
running = True
while running:
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            running = False
        if event.type == 500: #"ACCEL_UP":
            # Wrist moving up
            steps = steps + 1
        if event.type == 501: #"ACCEL_DOWN":
            # Wrist moving down
            steps = steps + 1
        if event.type == pygame.MOUSEBUTTONDOWN:
            pass

        # Increase steps when any key is pressed
        if event.type == pygame.KEYDOWN:
            steps += 1
            # Insert step into database
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "INSERT INTO steps (user_id, step, timestamp) VALUES (?, ?, ?)",
                (user_id, steps, timestamp)
            )
            conn.commit()

    # Periodically update graph (every 30 sec)
    if pygame.time.get_ticks() - graph_last_updated > 3_000:
        print("Updated graph.")
        graph_surface = draw_step_graph()
        graph_last_updated = pygame.time.get_ticks()

    # Fill screen with black
    screen.fill((0, 0, 0))

    # Draw the image at position (0, 0)
    screen.blit(image, (0, 0))

    # Render the text
    steps_text = font.render(f"Steps: {steps}", True, (255, 255, 255))  # White text
    screen.blit(steps_text, (20, 20))  # Draw text at top-left corner

    # Draw graph
    if graph_surface:
        graph_surface = pygame.transform.scale(graph_surface, (760, 150))
        screen.blit(graph_surface, (20, 420))


    # Update the display
    pygame.display.flip()
    clock.tick(15)

# Clean up
conn.close()
pygame.quit()
sys.exit()
