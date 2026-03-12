param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Args
)

$python = Get-Command python -ErrorAction SilentlyContinue
if ($python) {
    & $python.Source "freddy.py" @Args
    exit $LASTEXITCODE
}

$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) {
    & $py.Source -3 "freddy.py" @Args
    exit $LASTEXITCODE
}

Write-Error "Python 3.10+ was not found in PATH. Install Python and try again."
exit 1
