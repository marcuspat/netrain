# Visual Fixes Plan

## Issues Identified:

1. **ASCII Logo Overlap** ✓ Fixed
   - Removed the startup logo display that was overlapping with main UI
   - Added terminal.clear() to ensure clean slate

2. **Poor UI Formatting**
   - Need to improve layout constraints
   - Better color scheme
   - Cleaner borders and spacing
   - More organized information display

3. **Only DNS Packets Showing**
   - DNS detection in optimized.rs line 209 is too aggressive
   - It matches packets with very generic conditions
   - Need to improve protocol detection accuracy

## Implementation Plan:

### 1. Fix Protocol Detection
- Make DNS detection more specific
- Require proper DNS header structure
- Check for valid DNS flags and query format

### 2. Improve UI Layout
- Better proportions for panels
- Cleaner borders
- Improved color scheme
- Better text formatting

### 3. Enhanced Packet Display
- Show more packet details
- Color-code by protocol
- Add packet rate display
- Improve timestamp formatting