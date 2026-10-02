@{
  # Console tool: Write-Host output is intended (goes to the transcript)
  ExcludeRules = @('PSAvoidUsingWriteHost', 'PSUseApprovedVerbs', 'PSAvoidGlobalVars',
    # params used from nested functions / fixed Filter signature param($d, $x)
    'PSReviewUnusedParameter')
}
