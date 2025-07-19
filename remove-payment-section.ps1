$file = "ownerUI/frontend/ownerDashboard.html"
$jsFile = "ownerUI/frontend/ownerDashboard.js"

# First process the HTML file
$content = Get-Content -Raw $file
# Remove Payment History Section
$content = $content -replace '(?s)(<!-- Payment History Section -->.*?</div>\s*</div>\s*</div>\s*\n\s*)', ''
# Remove Pending Requests Section
$content = $content -replace '(?s)(<!-- Pending Requests Section -->.*?</div>\s*</div>\s*\n\s*)', ''
Set-Content -Path $file -Value $content

# Next process the JavaScript file
$jsContent = Get-Content -Raw $jsFile

# Remove fetchPendingClients function
$jsContent = $jsContent -replace '(?s)(async function fetchPendingClients\(\) \{.*?^\s*\})', ''

# Remove setupApprovalButtons function
$jsContent = $jsContent -replace '(?s)(function setupApprovalButtons\(\) \{.*?^\s*\})', ''

# Remove fetchPaymentHistory function
$jsContent = $jsContent -replace '(?s)(async function fetchPaymentHistory\(\) \{.*?^\s*\})', ''

# Remove function calls
$jsContent = $jsContent -replace 'fetchPendingClients\(\);', ''
$jsContent = $jsContent -replace 'fetchPaymentHistory\(\);', ''

# Write the modified JS file
Set-Content -Path $jsFile -Value $jsContent

Write-Host "Payment History and Pending Requests sections removed successfully from HTML and related JavaScript!" 