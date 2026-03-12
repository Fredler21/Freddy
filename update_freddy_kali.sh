#!/bin/bash
# update_freddy_kali.sh - Update Freddy on Kali Linux with latest 2,280-question bank

set -e  # Exit on error

echo "╔════════════════════════════════════════════════════════════╗"
echo "║        FREDDY KALI UPDATE - 2,280 Question Bank            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Detect Freddy directory
if [ -z "$FREDDY_HOME" ]; then
    FREDDY_HOME="$HOME/Freddy"
fi

if [ ! -d "$FREDDY_HOME" ]; then
    echo "❌ Freddy not found at $FREDDY_HOME"
    echo "   Please set FREDDY_HOME or clone Freddy first:"
    echo "   git clone https://github.com/Fredler21/Freddy.git ~/Freddy"
    exit 1
fi

cd "$FREDDY_HOME"
echo "📁 Freddy directory: $FREDDY_HOME"
echo ""

# Step 1: Update from GitHub
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 1: Pulling latest from GitHub..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

git fetch origin
git checkout main
git pull --ff-only origin main 2>/dev/null || git pull origin main
echo "✅ GitHub pull complete"
echo ""

# Step 2: Set up Python environment
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 2: Setting up Python environment..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate
python3 -m pip install --upgrade pip --quiet
pip install --no-cache-dir -r requirements.txt --quiet
echo "✅ Python environment ready"
echo ""

# Step 3: Index knowledge
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 3: Indexing knowledge base (this may take 5-15 minutes)..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo "⏳ Building vector store from 42 knowledge sources..."
python3 freddy.py learn
echo "✅ Knowledge indexing complete"
echo ""

# Step 4: Verify installation
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 4: Verifying installation..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check vector store
if [ -d ".freddy/vector_store" ]; then
    SIZE=$(du -sh .freddy/vector_store | cut -f1)
    echo "✅ Vector store created ($SIZE)"
else
    echo "❌ Vector store not found - something went wrong"
    exit 1
fi

# Check question bank
if [ -f "questions/question_bank.jsonl" ]; then
    COUNT=$(wc -l < questions/question_bank.jsonl)
    echo "✅ Question bank loaded ($COUNT questions)"
else
    echo "⚠️  Question bank not found - regenerating..."
    python3 generate_question_bank.py --format jsonl
fi

echo ""

# Step 5: Quick test
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Step 5: Quick functionality test..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo ""
echo "Testing: python3 freddy.py knowledge-search 'SSH hardening'"
echo "─────────────────────────────────────────────────────────────"
python3 freddy.py knowledge-search "SSH hardening" | head -10
echo ""

# Summary
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    UPDATE COMPLETE! ✅                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📊 FREDDY NOW INCLUDES:"
echo "   ✓ 2,280 Questions (semantic variations + platform contexts)"
echo "   ✓ 42 Knowledge Sources (NIST, RFC, OWASP, etc.)"
echo "   ✓ 12 Question Intents (what-is, how-fix, best-practices, etc.)"
echo "   ✓ 3 Difficulty Levels (beginner, intermediate, advanced)"
echo ""
echo "🚀 NEXT STEPS:"
echo "   1. Test knowledge-search: python3 freddy.py knowledge-search 'your question'"
echo "   2. Review question bank: python3 verify_question_coverage.py"
echo "   3. Run scans: python3 freddy.py scan <target>"
echo ""
echo "📖 DOCUMENTATION:"
echo "   • Main docs: README.md"
echo "   • Question bank: questions/README.md"
echo "   • Kali guide: KALI_UPDATE_GUIDE.md"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
