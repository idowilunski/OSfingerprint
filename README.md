# OSfingerprint

// load db 
// 


class OsFingerprintsDb
{
public:
void Load(dbFilePath); // load from input the db into m_osFingerprints

SearchAggressive()
{
search(); 
go over results - if X matches, return; 
}

SearchIdentical()
{
search();
go over results - if ALL matches, return; 
}

private:
vector<OsScanResult> Search(t1,t2,t3,t4,...); // return os name or "N/A" if fingerprint is not found - vector of all options in case of aggressive guess, incase of normal guess it'll be 1 os. 



set<Fingerprint> m_osType; [os1, os2]
}

//TODO : what happens in case of aggressive guesses? 
class OsScanResult
{
int countMatchedResult; 
osType; ... (scan info) 
}


class OStype
{
//struct that contains all checks values and an "equals" operator that allows checking whether one fingerprint is equal to another 
name (str)
resultForT1 
resultForT2 
}

Service
{
//Maybe we don't need this wrapper if we have osChecker
Fingerprint AnalyzeOs(ipAddr); //gets a remote ip to analyze and runs the tests on it, calls osChecker
}

OsChecker
{
private:
runCheck(funcPtr[?], result);

public:
OsType(name?) runAllChecks(); //iterate over all checks in loop and call runCheck on each
}

Check 
{
RequestPacket Prepare();
ResponsePacket Send(requestPacket);
someValueType Analyze(responsePacket);
}

CheckT1 : Check 
{
RequestPacket Prepare();
someValueType Analyze(responsePacket);
}
...


value types (I think) can be - bool, enum, strings and integers. 


main:
db = new Db();
db.LoadDb()
res (osType without name) = RunAllChecks()
foundOS = db.Search(res)
presentResult(foundOs)


 
