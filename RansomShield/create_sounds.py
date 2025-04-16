"""
Script to create placeholder sound files for the Ransomware Detection Framework.
Creates WAV files for different alert severity levels.
"""

import os
import wave
import struct
import math


def generate_sine_wave(frequency, duration, volume=0.5, sample_rate=44100):
    """Generate a sine wave with the given frequency and duration."""
    # Calculate the number of frames needed
    n_frames = int(sample_rate * duration)
    
    # Create an empty array to store the frames
    frames = []
    
    # Generate the sine wave frames
    for i in range(n_frames):
        # Calculate the value of the sine wave at this frame
        value = volume * math.sin(2 * math.pi * frequency * i / sample_rate)
        
        # Convert the value to a 16-bit signed integer
        frame = struct.pack('<h', int(value * 32767))
        
        # Add the frame to the array
        frames.append(frame)
    
    # Join all frames into a byte string
    return b''.join(frames)


def create_sound_file(file_path, frequencies, duration, volume=0.5):
    """Create a WAV file with the given frequencies and duration."""
    # Create the directory if it doesn't exist
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    
    # Create a WAV file with the given filename
    with wave.open(file_path, 'wb') as wav_file:
        # Set WAV file parameters
        n_channels = 1  # Mono
        sample_width = 2  # 2 bytes (16-bit)
        sample_rate = 44100  # 44.1 kHz
        
        # Set the WAV file header
        wav_file.setnchannels(n_channels)
        wav_file.setsampwidth(sample_width)
        wav_file.setframerate(sample_rate)
        
        # Generate the sine wave frames for each frequency
        for frequency in frequencies:
            frames = generate_sine_wave(frequency, duration / len(frequencies), volume, sample_rate)
            wav_file.writeframes(frames)


def main():
    """Create placeholder sound files for different severity levels."""
    # Define the directory for the sound files
    sounds_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "sounds")
    
    # Create the directory if it doesn't exist
    os.makedirs(sounds_dir, exist_ok=True)
    
    # Create the sound files
    
    # Critical alert - Higher frequencies, faster beeps
    create_sound_file(
        os.path.join(sounds_dir, "alert_critical.wav"),
        [800, 0, 800, 0, 800],  # High frequency beeps
        0.6,  # Short duration
        0.7   # Higher volume
    )
    
    # Warning alert - Medium frequencies, medium beeps
    create_sound_file(
        os.path.join(sounds_dir, "alert_warning.wav"),
        [500, 0, 500],  # Medium frequency beeps
        0.6,  # Medium duration
        0.6   # Medium volume
    )
    
    # Info alert - Lower frequencies, longer beeps
    create_sound_file(
        os.path.join(sounds_dir, "alert_info.wav"),
        [300, 0],  # Low frequency beep
        0.5,  # Longer duration
        0.5   # Lower volume
    )
    
    print("Sound files created successfully!")


if __name__ == "__main__":
    main()