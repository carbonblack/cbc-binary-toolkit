rule CompanyMatch
{
    meta:
      sev = 2
    strings:
       $microsoft = "microsoft" nocase
       $google = "google" nocase

    condition:
       $microsoft or $google
}
