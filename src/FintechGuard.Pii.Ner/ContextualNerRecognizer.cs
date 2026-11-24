using FintechGuard.Pii.Context;
using FintechGuard.Pii.Core;
using FintechGuard.Pii.Recognizers;

namespace FintechGuard.Pii.Ner;

/// <summary>
/// Tier 1 pure-CPU Named Entity Recognition (NER) without neural model overhead (~20-150 us/field).
/// Combines an O(n) Aho-Corasick trigger automaton, multilingual English + Hindi Devanagari patterns,
/// curated Indian + global name lexicons, and structural address detection.
/// </summary>
public sealed class ContextualNerRecognizer : IFastPiiRecognizer
{
    public string Name => _options.Name;
    public PiiType PiiType => PiiType.PersonName;

    private readonly ContextualNerOptions _options;
    private readonly double _confidence;

    private readonly AhoCorasickMatcher _personTriggerMatcher;
    private readonly AhoCorasickMatcher _addressKeywordMatcher;
    private readonly AhoCorasickMatcher _addressTriggerMatcher;
    private readonly AhoCorasickMatcher _orgSuffixMatcher;

    private readonly HashSet<string> _firstNames;
    private readonly HashSet<string> _lastNames;
    private readonly HashSet<string> _stopWords;
    private readonly HashSet<string> _hindiStopWords;
    private readonly HashSet<string> _addressKeywords;
    private readonly HashSet<string> _explicitPersonKeys;

    private static readonly string[] PersonTriggers =
    [
        "mr. ", "mrs. ", "ms. ", "dr. ", "prof. ", "adv. ",
        "mr ", "mrs ", "ms ", "dr ", "shri ", "smt. ", "smt ", "kumari ",
        "my name is ", "customer name is ", "customer name: ", "customer name:",
        "account holder is ", "account holder: ", "account holder:",
        "full name: ", "full name:", "name is ", "name: ", "name:",
        "spoke to ", "talking to ", "called by ", "contact person: ", "contact person:",
        "beneficiary: ", "beneficiary:", "agent ",
        "कस्टमर का नाम ", "ग्राहक का नाम ", "मेरा नाम ", "लाभार्थी का नाम ", "नाम "
    ];

    private static readonly string[] AddressTriggers =
    [
        "residing at ", "resident of ", "address: ", "address:", "shipping to ", "located at ",
        "पता: ", "पता:", "पता "
    ];

    private static readonly string[] DefaultAddressKeywords =
    [
        "road", "rd", "street", "st", "lane", "ln", "nagar", "colony", "layout", "sector",
        "phase", "cross", "main", "enclave", "vihar", "marg", "chowk", "avenue", "ave",
        "boulevard", "blvd", "apartment", "apt", "flat", "plot", "floor", "tower",
        "residency", "extension", "extn", "block", "circle", "park", "bazaar", "bazar"
    ];

    private static readonly string[] OrgSuffixes =
    [
        "private limited", "pvt ltd", "pvt. ltd.", "pvt. ltd", "limited", "ltd.", "ltd",
        "llp", "inc.", "inc", "corp.", "corp", "corporation", "llc", "gmbh",
        "technologies", "solutions", "finserv", "payments", "bank"
    ];

    private static readonly string[] DefaultFirstNames =
    [
        // Indian first names
        "Aarav", "Aakash", "Abhishek", "Aditya", "Ajay", "Akash", "Akshay", "Alok", "Aman", "Amit",
        "Amol", "Anand", "Ananya", "Anil", "Anjali", "Ankit", "Ankur", "Anurag", "Arjun", "Arun",
        "Arvind", "Asha", "Ashish", "Ashok", "Ashwin", "Avinash", "Ayush", "Bhavesh", "Bikram", "Chandan",
        "Chetan", "Deepak", "Deepika", "Dev", "Devika", "Dinesh", "Divya", "Gaurav", "Gautam", "Geeta",
        "Girish", "Gopal", "Harish", "Harsh", "Hemant", "Hitesh", "Ishaan", "Jagdish", "Jatin", "Jay",
        "Jaya", "Kajal", "Kamal", "Kapil", "Karan", "Karthik", "Kavita", "Kiran", "Kishore", "Krishna",
        "Kunal", "Lakshmi", "Lalit", "Madhav", "Mahesh", "Manish", "Manoj", "Meena", "Meera", "Mihir",
        "Mohan", "Mohit", "Mukesh", "Nandini", "Naresh", "Naveen", "Neeraj", "Neha", "Nikhil", "Nilesh",
        "Nisha", "Nitin", "Pankaj", "Parth", "Pavan", "Pooja", "Pradeep", "Prakash", "Pranav", "Prashant",
        "Pratik", "Praveen", "Preeti", "Priya", "Puneet", "Rahul", "Raj", "Rajesh", "Rajeev", "Rajiv",
        "Rakesh", "Ram", "Ramesh", "Ranjan", "Rashmi", "Ravi", "Rekha", "Rishabh", "Rohan", "Rohit",
        "Ruchika", "Sachin", "Sagar", "Sahil", "Sandeep", "Sanjay", "Sanjeev", "Santosh", "Sarita", "Saurabh",
        "Seema", "Shalini", "Shankar", "Shashank", "Shikha", "Shiv", "Shivam", "Shreya", "Siddharth", "Simran",
        "Sneha", "Sonia", "Sujata", "Sumit", "Sunil", "Sunita", "Suraj", "Suresh", "Surya", "Swati",
        "Tanvi", "Tarun", "Tushar", "Uday", "Umesh", "Vaibhav", "Vandana", "Varun", "Vijay", "Vikas",
        "Vikram", "Vinay", "Vineet", "Vinod", "Vishal", "Vivek", "Yash", "Yogesh", "रवि", "संजय", "विक्रम", "प्रिया", "राहुल",
        // Global first names
        "Aaron", "Adam", "Alex", "Alexander", "Alice", "Amanda", "Andrew", "Angela", "Anna", "Anthony",
        "Arthur", "Benjamin", "Brandon", "Brian", "Carlos", "Catherine", "Charles", "Charlotte", "Chris", "Christian",
        "Christopher", "Claire", "Daniel", "David", "Dennis", "Diana", "Donald", "Edward", "Elena", "Elizabeth",
        "Emily", "Emma", "Eric", "Ethan", "Evelyn", "Frank", "Gabriel", "George", "Grace", "Hannah",
        "Henry", "Jacob", "James", "Jason", "Jennifer", "Jessica", "John", "Jonathan", "Joseph", "Joshua",
        "Julia", "Justin", "Karen", "Katherine", "Keith", "Kevin", "Laura", "Lauren", "Liam", "Linda",
        "Lisa", "Lucas", "Luke", "Maria", "Mark", "Martin", "Mary", "Matthew", "Megan", "Michael",
        "Michelle", "Nathan", "Nicholas", "Noah", "Oliver", "Olivia", "Patrick", "Paul", "Peter", "Philip",
        "Rachel", "Rebecca", "Richard", "Robert", "Ryan", "Samuel", "Sarah", "Scott", "Sean", "Sophia",
        "Stephen", "Steven", "Susan", "Thomas", "Timothy", "Tyler", "Victoria", "William"
    ];

    private static readonly string[] DefaultLastNames =
    [
        // Indian surnames
        "Agarwal", "Aggarwal", "Ahuja", "Anand", "Ansari", "Arora", "Awasthi", "Bajaj", "Banerjee", "Bansal",
        "Bhat", "Bhatia", "Bhattacharya", "Bose", "Chakraborty", "Chatterjee", "Chaudhary", "Chauhan", "Chopra", "Choudhary",
        "Das", "Datta", "Desai", "Deshmukh", "Deshpande", "Dhillon", "Dixit", "Dubey", "Dutta", "Gandhi",
        "Ganguly", "Garg", "Ghosh", "Gill", "Goel", "Goyal", "Grewal", "Gupta", "Hegde", "Iyer",
        "Iyengar", "Jain", "Jaiswal", "Jha", "Joshi", "Kapoor", "Kapur", "Kashyap", "Kaul", "Kaur",
        "Khan", "Khanna", "Khatri", "Kulkarni", "Kumar", "Kumari", "Lal", "Mahajan", "Malhotra", "Malik",
        "Mehta", "Menon", "Mishra", "Mittal", "Modi", "Mohanty", "Mukherjee", "Murthy", "Nair", "Nambiar",
        "Nanda", "Narang", "Nayak", "Negi", "Pai", "Panda", "Pandey", "Parekh", "Patel", "Pathak",
        "Patil", "Pawar", "Pillai", "Prabhu", "Pradhan", "Prasad", "Purohit", "Raghavan", "Rai", "Rajput",
        "Ramachandran", "Rana", "Rao", "Rathore", "Reddy", "Roy", "Saha", "Sahoo", "Saxena", "Sen",
        "Sethi", "Shah", "Sharma", "Shastri", "Shetty", "Shinde", "Shukla", "Singh", "Sinha", "Sood",
        "Srivastava", "Subramanian", "Sundaram", "Swaminathan", "Thakur", "Tiwari", "Tripathi", "Trivedi", "Upadhyay", "Varma",
        "Verma", "Vyas", "Yadav", "कुमार", "शर्मा", "पटेल", "वर्मा", "सिंह",
        // Global surnames
        "Adams", "Allen", "Anderson", "Baker", "Barnes", "Bell", "Bennett", "Brooks", "Brown", "Campbell",
        "Carter", "Clark", "Collins", "Cook", "Cooper", "Cox", "Davis", "Doe", "Edwards", "Evans",
        "Fisher", "Foster", "Garcia", "Gomez", "Gonzalez", "Gray", "Green", "Hall", "Harris", "Hernandez",
        "Hill", "Howard", "Hughes", "Jackson", "James", "Jenkins", "Johnson", "Jones", "Kelly", "King",
        "Lee", "Lewis", "Long", "Lopez", "Martin", "Martinez", "Miller", "Mitchell", "Moore", "Morgan",
        "Morris", "Murphy", "Myers", "Nelson", "Nguyen", "Parker", "Patterson", "Perez", "Perry", "Peterson",
        "Phillips", "Powell", "Price", "Ramirez", "Reed", "Richardson", "Rivera", "Roberts", "Robinson", "Rodriguez",
        "Rogers", "Ross", "Russell", "Sanchez", "Sanders", "Scott", "Smith", "Stewart", "Sullivan", "Taylor",
        "Thomas", "Thompson", "Torres", "Turner", "Walker", "Ward", "Watson", "White", "Williams", "Wilson",
        "Wood", "Wright", "Young"
    ];

    private static readonly string[] DefaultStopWords =
    [
        "the", "a", "an", "and", "or", "but", "for", "nor", "so", "yet", "about", "above", "across",
        "after", "against", "along", "among", "around", "at", "before", "behind", "below", "beneath",
        "beside", "between", "beyond", "by", "down", "during", "except", "from", "in", "inside",
        "into", "like", "near", "of", "off", "on", "onto", "out", "outside", "over", "past", "regarding",
        "since", "through", "throughout", "to", "toward", "under", "until", "up", "upon", "with", "within",
        "without", "is", "are", "was", "were", "be", "been", "being", "have", "has", "had", "do", "does",
        "did", "will", "would", "shall", "should", "can", "could", "may", "might", "must", "who", "whom",
        "whose", "which", "that", "this", "these", "those", "he", "she", "it", "they", "we", "you", "i",
        "his", "her", "their", "our", "your", "my", "called", "connected", "said", "told", "reported",
        "issue", "resolved", "ticket", "support", "customer", "user", "client", "agent", "account",
        "payment", "transfer", "transaction", "order", "invoice", "credit", "debit", "card", "number",
        "bank", "limited", "ltd", "pvt", "private", "solutions", "services", "technologies", "systems",
        "global", "india", "reserve", "gateway", "approved", "declined", "confirmed", "regular", "ledger",
        "entry", "status", "details", "notes", "summary", "email", "phone", "mobile", "address", "pan",
        "aadhaar", "gstin", "ifsc", "upi", "iban", "ssn", "road", "street", "nagar", "sector", "flat",
        "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
        "january", "february", "march", "april", "june", "july", "august", "september", "october", "november", "december",
        "bengaluru", "bangalore", "mumbai", "delhi", "chennai", "hyderabad", "pune", "kolkata", "gurgaon", "noida"
    ];

    private static readonly string[] DefaultHindiStopWords =
    [
        "है", "हैं", "था", "थी", "थे", "हूँ", "हो", "को", "का", "की", "के", "ने", "से", "में", "पर",
        "और", "तथा", "या", "एक", "यह", "वह", "किया", "गया", "हुआ", "कहा", "बोला", "कार्ड", "नंबर",
        "खाता", "पेमेंट", "बैंक", "ग्राहक", "कस्टमर", "पता", "फ़ोन", "मोबाइल"
    ];

    public ContextualNerRecognizer(ContextualNerOptions? options = null)
    {
        _options = options ?? new ContextualNerOptions();
        _confidence = Math.Clamp(_options.Confidence, 0.0, 1.0);

        _firstNames = new HashSet<string>(DefaultFirstNames, StringComparer.OrdinalIgnoreCase);
        foreach (var fn in _options.AdditionalFirstNames) _firstNames.Add(fn);

        _lastNames = new HashSet<string>(DefaultLastNames, StringComparer.OrdinalIgnoreCase);
        foreach (var ln in _options.AdditionalLastNames) _lastNames.Add(ln);

        _stopWords = new HashSet<string>(DefaultStopWords, StringComparer.OrdinalIgnoreCase);
        foreach (var sw in _options.StopWords) _stopWords.Add(sw);

        _hindiStopWords = new HashSet<string>(DefaultHindiStopWords, StringComparer.Ordinal);

        _addressKeywords = new HashSet<string>(DefaultAddressKeywords, StringComparer.OrdinalIgnoreCase);
        foreach (var ak in _options.AdditionalAddressKeywords) _addressKeywords.Add(ak);

        _explicitPersonKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "name", "customer_name", "full_name", "holder", "account_holder", "beneficiary", "first_name", "last_name", "payee_name"
        };

        _personTriggerMatcher = new AhoCorasickMatcher(PersonTriggers);
        _addressKeywordMatcher = new AhoCorasickMatcher(_addressKeywords.ToArray());
        _addressTriggerMatcher = new AhoCorasickMatcher(AddressTriggers);
        _orgSuffixMatcher = new AhoCorasickMatcher(OrgSuffixes);
    }

    public bool MightMatch(in TextFeatures features)
    {
        if (features.Length < 2)
            return false;

        if (_options.TargetKeys.Length > 0)
            return features.HasAsciiUpper || features.HasNonAscii || features.HasDigit;

        if (!_options.AutoGateUnstructuredText)
            return true;

        // Skip short codes, pure numbers, single-word ALL-CAPS enum strings, and emails
        if (features.WordCount >= 2 || features.HasNonAscii)
            return true;

        return features.HasAsciiUpper && features.HasAsciiLower && features.Length >= 3 && features.DigitCount == 0 && !features.HasAt;
    }

    public IEnumerable<PiiMatch> Recognize(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<PiiMatch>();

        var features = TextFeatures.Analyze(text.AsSpan());
        if (!MightMatch(in features))
            return Array.Empty<PiiMatch>();

        var list = new List<PiiMatch>(2);
        var ctx = new RecognitionContext();
        RecognizeInto(text, in ctx, in features, list);
        return list;
    }

    public IEnumerable<PiiMatch> Recognize(string text, RecognitionContext context)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Array.Empty<PiiMatch>();

        var features = TextFeatures.Analyze(text.AsSpan());
        if (!MightMatch(in features))
            return Array.Empty<PiiMatch>();

        var list = new List<PiiMatch>(2);
        RecognizeInto(text, in context, in features, list);
        return list;
    }

    public void RecognizeInto(string text, in RecognitionContext context, in TextFeatures features, List<PiiMatch> destination)
    {
        if (string.IsNullOrWhiteSpace(text) || !MightMatch(in features))
            return;

        if (_options.TargetKeys.Length > 0 && context.PropertyName != null)
        {
            if (!KeyHintRegistry.MatchesAnyTargetKey(context.PropertyName, _options.TargetKeys))
                return;
        }

        ReadOnlySpan<char> span = text.AsSpan();
        var acMatches = new List<AhoCorasickMatch>(8);

        if (_options.DetectPersonNames)
        {
            DetectPersons(text, span, context.PropertyName, acMatches, destination);
        }

        if (_options.DetectAddresses)
        {
            acMatches.Clear();
            DetectAddresses(text, span, context.PropertyName, acMatches, destination);
        }

        if (_options.DetectOrganizations)
        {
            acMatches.Clear();
            DetectOrganizations(text, span, acMatches, destination);
        }
    }

    private void DetectPersons(
        string text,
        ReadOnlySpan<char> span,
        string? propertyName,
        List<AhoCorasickMatch> acMatches,
        List<PiiMatch> destination)
    {
        // 1. Trigger & Honorific-anchored extraction ("Mr. ...", "my name is ...", "कस्टमर का नाम ...")
        _personTriggerMatcher.FindMatches(span, acMatches);
        for (int i = 0; i < acMatches.Count; i++)
        {
            var m = acMatches[i];
            if (m.Start > 0 && char.IsLetterOrDigit(span[m.Start - 1]))
                continue;

            bool isHonorific = m.PatternIndex <= 13;
            int cursor = m.Start + m.Length;
            if (TryExtractNameSpan(text, span, cursor, maxTokens: 3, requireTitleOrDevanagari: true, out int nameStart, out int nameLen, out int tokCount))
            {
                if (!isHonorific || tokCount >= 1)
                {
                    // For honorifics like "Mr. Rajesh Verma", optionally include honorific? No, mask the person's actual name!
                    AddUniqueMatch(destination, text, nameStart, nameLen, PiiType.PersonName, _confidence);
                }
            }
        }

        // 2. Lexicon-driven scanning over word tokens (2-word TitleCase First+Last, or 1-word under explicit person key)
        bool explicitPersonKey = propertyName != null &&
            (_explicitPersonKeys.Contains(propertyName) ||
             _explicitPersonKeys.Any(k => KeyHintRegistry.MatchesAnyTargetKey(propertyName, [k])));

        Span<(int Start, int Length)> tokens = stackalloc (int, int)[128];
        int tokenCount = TokenizeWords(span, tokens);

        for (int i = 0; i < tokenCount; i++)
        {
            var t1 = tokens[i];
            string w1 = text.Substring(t1.Start, t1.Length);

            if (_stopWords.Contains(w1) || _hindiStopWords.Contains(w1))
                continue;

            bool w1IsFirst = _firstNames.Contains(w1);
            bool w1TitleOrDevanagari = IsCapitalizedOrDevanagari(w1.AsSpan());

            if (!w1TitleOrDevanagari)
                continue;

            // Check 2-word (or 3-word) Name sequence
            if (i + 1 < tokenCount)
            {
                var t2 = tokens[i + 1];
                // Must be separated only by single whitespace
                if (IsSimpleSpaceGap(span, t1.Start + t1.Length, t2.Start))
                {
                    string w2 = text.Substring(t2.Start, t2.Length);
                    if (!_stopWords.Contains(w2) && !_hindiStopWords.Contains(w2) && IsCapitalizedOrDevanagari(w2.AsSpan()))
                    {
                        bool w2IsLast = _lastNames.Contains(w2);
                        if ((w1IsFirst && w2IsLast) || (w1IsFirst && w2.Length >= 2) || (explicitPersonKey && w2.Length >= 2))
                        {
                            int endPos = t2.Start + t2.Length;
                            // Optional 3rd surname token if 2nd was middle name/initial and 3rd is known surname
                            if (i + 2 < tokenCount)
                            {
                                var t3 = tokens[i + 2];
                                if (IsSimpleSpaceGap(span, t2.Start + t2.Length, t3.Start))
                                {
                                    string w3 = text.Substring(t3.Start, t3.Length);
                                    if (!_stopWords.Contains(w3) && _lastNames.Contains(w3))
                                    {
                                        endPos = t3.Start + t3.Length;
                                        i++;
                                    }
                                }
                            }

                            AddUniqueMatch(destination, text, t1.Start, endPos - t1.Start, PiiType.PersonName, _confidence);
                            i++;
                            continue;
                        }
                    }
                }
            }

            // Single-token match ONLY when under an explicit person-name key (e.g. "customer_name": "Vikram")
            if (explicitPersonKey && (w1IsFirst || _lastNames.Contains(w1)))
            {
                AddUniqueMatch(destination, text, t1.Start, t1.Length, PiiType.PersonName, _confidence);
            }
        }
    }

    private bool TryExtractNameSpan(
        string text,
        ReadOnlySpan<char> span,
        int startCursor,
        int maxTokens,
        bool requireTitleOrDevanagari,
        out int matchStart,
        out int matchLength,
        out int extractedTokenCount)
    {
        matchStart = -1;
        matchLength = 0;
        extractedTokenCount = 0;

        int i = startCursor;
        while (i < span.Length && char.IsWhiteSpace(span[i])) i++;
        if (i >= span.Length) return false;

        int spanStart = i;
        int spanEnd = i;
        int count = 0;

        while (i < span.Length && count < maxTokens)
        {
            while (i < span.Length && (span[i] == ' ' || span[i] == '\t')) i++;
            if (i >= span.Length) break;

            // Stop at punctuation delimiters
            char c = span[i];
            if (c == ',' || c == '.' || c == ';' || c == ':' || c == '!' || c == '?' ||
                c == '(' || c == ')' || c == '[' || c == ']' || c == '"' || c == '\n' || c == '\r' || c == '।')
                break;

            int tokStart = i;
            while (i < span.Length && !char.IsWhiteSpace(span[i]) &&
                   span[i] != ',' && span[i] != ';' && span[i] != ':' &&
                   span[i] != '!' && span[i] != '?' && span[i] != ')' && span[i] != '।' &&
                   !(span[i] == '.' && (i + 1 == span.Length || char.IsWhiteSpace(span[i + 1]) || span[i + 1] == ',')))
            {
                i++;
            }

            int tokLen = i - tokStart;
            if (tokLen == 0) break;

            ReadOnlySpan<char> tok = span.Slice(tokStart, tokLen);
            if (!IsValidNameToken(tok, requireTitleOrDevanagari))
                break;

            string tokStr = text.Substring(tokStart, tokLen);
            if (_stopWords.Contains(tokStr) || _hindiStopWords.Contains(tokStr))
                break;

            // Include trailing period only for middle/first initial like "K."
            if (tokLen == 1 && i < span.Length && span[i] == '.')
                i++;

            if (count == 0) spanStart = tokStart;
            spanEnd = i;
            count++;

            if (i < span.Length && span[i] == '.')
                break;
        }

        if (count == 0) return false;

        matchStart = spanStart;
        matchLength = spanEnd - spanStart;
        extractedTokenCount = count;
        return true;
    }

    private void DetectAddresses(
        string text,
        ReadOnlySpan<char> span,
        string? propertyName,
        List<AhoCorasickMatch> acMatches,
        List<PiiMatch> destination)
    {
        bool explicitAddressKey = propertyName != null &&
            KeyHintRegistry.MatchesAnyTargetKey(propertyName, ["address", "street", "residence", "billing_address", "shipping_address"]);

        // If entire field is an explicit address key with >= 2 words and >= 8 chars, mask whole value if it contains digits or address keyword
        _addressTriggerMatcher.FindMatches(span, acMatches);
        for (int i = 0; i < acMatches.Count; i++)
        {
            var t = acMatches[i];
            if (t.Start > 0 && char.IsLetterOrDigit(span[t.Start - 1]))
                continue;

            int addrStart = t.Start + t.Length;
            while (addrStart < span.Length && char.IsWhiteSpace(span[addrStart])) addrStart++;
            if (addrStart >= span.Length) continue;

            int addrEnd = ScanForwardToSentenceEnd(span, addrStart);
            TrimTrailingWhitespaceAndPunct(span, ref addrStart, ref addrEnd);
            if (addrEnd - addrStart >= 6)
            {
                AddUniqueMatch(destination, text, addrStart, addrEnd - addrStart, PiiType.Address, _confidence);
            }
        }

        acMatches.Clear();
        _addressKeywordMatcher.FindMatches(span, acMatches);
        if (acMatches.Count == 0 && !explicitAddressKey)
            return;

        // Validate word boundaries on keyword matches
        for (int i = 0; i < acMatches.Count; i++)
        {
            var kw = acMatches[i];
            if (kw.Start > 0 && char.IsLetterOrDigit(span[kw.Start - 1]))
                continue;
            int kwEnd = kw.Start + kw.Length;
            if (kwEnd < span.Length && char.IsLetterOrDigit(span[kwEnd]))
                continue;

            // Expand backward to start of clause / house number / flat prefix
            int addrStart = ExpandAddressBackward(span, kw.Start);
            int addrEnd = ExpandAddressForward(span, kwEnd);
            TrimTrailingWhitespaceAndPunct(span, ref addrStart, ref addrEnd);

            ReadOnlySpan<char> candidate = span.Slice(addrStart, addrEnd - addrStart);
            if (candidate.Length < 8)
                continue;

            // Require structural signal: contains at least one digit (house/flat/sector/PIN) OR 2+ address keywords OR explicit address JSON key
            bool hasDigit = ContainsDigit(candidate);
            if (hasDigit || explicitAddressKey || CountAddressKeywordsInSpan(candidate, acMatches, addrStart, addrEnd) >= 2)
            {
                AddUniqueMatch(destination, text, addrStart, addrEnd - addrStart, PiiType.Address, _confidence);
            }
        }
    }

    private void DetectOrganizations(
        string text,
        ReadOnlySpan<char> span,
        List<AhoCorasickMatch> acMatches,
        List<PiiMatch> destination)
    {
        _orgSuffixMatcher.FindMatches(span, acMatches);
        for (int i = 0; i < acMatches.Count; i++)
        {
            var m = acMatches[i];
            if (m.Start > 0 && char.IsLetterOrDigit(span[m.Start - 1]))
                continue;
            int end = m.Start + m.Length;
            if (end < span.Length && char.IsLetterOrDigit(span[end]))
                continue;

            // Walk backward up to 4 TitleCase words
            int pos = m.Start;
            int wordsFound = 0;
            int bestStart = m.Start;
            while (pos > 0 && wordsFound < 4)
            {
                while (pos > 0 && span[pos - 1] == ' ') pos--;
                if (pos == 0) break;

                int wEnd = pos;
                while (pos > 0 && (char.IsLetterOrDigit(span[pos - 1]) || span[pos - 1] == '&' || span[pos - 1] == '-'))
                    pos--;

                if (pos == wEnd) break;
                ReadOnlySpan<char> word = span.Slice(pos, wEnd - pos);
                if (!char.IsUpper(word[0]))
                    break;

                string wordStr = text.Substring(pos, wEnd - pos);
                if (_stopWords.Contains(wordStr))
                    break;

                bestStart = pos;
                wordsFound++;
            }

            if (wordsFound >= 1)
            {
                AddUniqueMatch(destination, text, bestStart, end - bestStart, PiiType.Organization, _confidence);
            }
        }
    }

    private static int ExpandAddressBackward(ReadOnlySpan<char> span, int kwStart)
    {
        int pos = kwStart;
        int commasSeen = 0;
        int wordsScanned = 0;

        while (pos > 0 && wordsScanned < 8)
        {
            char prev = span[pos - 1];
            if (prev == ':' || prev == ';' || prev == '.' || prev == '\n' || prev == '\r')
                break;

            if (prev == ',')
            {
                commasSeen++;
                if (commasSeen > 2) break;
                pos--;
                continue;
            }

            if (prev == ' ' || prev == '\t')
            {
                pos--;
                continue;
            }

            int wEnd = pos;
            while (pos > 0 && !char.IsWhiteSpace(span[pos - 1]) && span[pos - 1] != ',' &&
                   span[pos - 1] != ':' && span[pos - 1] != ';' && span[pos - 1] != '.')
            {
                pos--;
            }

            ReadOnlySpan<char> tok = span.Slice(pos, wEnd - pos);
            // Stop at lowercase preposition/verb boundaries like "at", "in", "to", "from", "near" unless digit/flat/no precedes
            if (tok.Equals("at", StringComparison.OrdinalIgnoreCase) ||
                tok.Equals("in", StringComparison.OrdinalIgnoreCase) ||
                tok.Equals("to", StringComparison.OrdinalIgnoreCase) ||
                tok.Equals("from", StringComparison.OrdinalIgnoreCase) ||
                tok.Equals("lives", StringComparison.OrdinalIgnoreCase) ||
                tok.Equals("resides", StringComparison.OrdinalIgnoreCase))
            {
                pos = wEnd;
                break;
            }

            wordsScanned++;
        }

        while (pos < kwStart && (char.IsWhiteSpace(span[pos]) || span[pos] == ','))
            pos++;

        return pos;
    }

    private static int ExpandAddressForward(ReadOnlySpan<char> span, int kwEnd)
    {
        int i = kwEnd;
        int commas = 0;
        while (i < span.Length)
        {
            char c = span[i];
            if (c == '.' || c == ';' || c == '\n' || c == '\r' || c == '!' || c == '?')
                break;
            if (c == ',')
            {
                commas++;
                if (commas > 3) break;
            }
            i++;
        }
        return i;
    }

    private static int ScanForwardToSentenceEnd(ReadOnlySpan<char> span, int start)
    {
        int i = start;
        while (i < span.Length)
        {
            char c = span[i];
            if (c == '.' || c == ';' || c == '\n' || c == '\r' || c == '!' || c == '?')
                break;
            i++;
        }
        return i;
    }

    private static void TrimTrailingWhitespaceAndPunct(ReadOnlySpan<char> span, ref int start, ref int end)
    {
        while (start < end && (char.IsWhiteSpace(span[start]) || span[start] == ',')) start++;
        while (end > start && (char.IsWhiteSpace(span[end - 1]) || span[end - 1] == ',')) end--;
    }

    private static bool ContainsDigit(ReadOnlySpan<char> span)
    {
        for (int i = 0; i < span.Length; i++)
        {
            if (char.IsDigit(span[i])) return true;
        }
        return false;
    }

    private static int CountAddressKeywordsInSpan(ReadOnlySpan<char> _, List<AhoCorasickMatch> acMatches, int start, int end)
    {
        int count = 0;
        for (int i = 0; i < acMatches.Count; i++)
        {
            if (acMatches[i].Start >= start && acMatches[i].Start + acMatches[i].Length <= end)
                count++;
        }
        return count;
    }

    private static int TokenizeWords(ReadOnlySpan<char> span, Span<(int Start, int Length)> tokens)
    {
        int count = 0;
        int i = 0;
        while (i < span.Length && count < tokens.Length)
        {
            while (i < span.Length && !IsLetterOrDevanagari(span[i])) i++;
            if (i >= span.Length) break;

            int start = i;
            while (i < span.Length && IsLetterOrDevanagari(span[i])) i++;

            // Ensure token isn't attached to digits or underscores (e.g. TXN_123)
            bool leftAttached = start > 0 && (char.IsDigit(span[start - 1]) || span[start - 1] == '_');
            bool rightAttached = i < span.Length && (char.IsDigit(span[i]) || span[i] == '_');
            if (!leftAttached && !rightAttached)
            {
                tokens[count++] = (start, i - start);
            }
        }
        return count;
    }

    private static bool IsSimpleSpaceGap(ReadOnlySpan<char> span, int gapStart, int gapEnd)
    {
        if (gapEnd <= gapStart || gapEnd - gapStart > 2)
            return false;
        for (int i = gapStart; i < gapEnd; i++)
        {
            if (span[i] != ' ') return false;
        }
        return true;
    }

    private static bool IsValidNameToken(ReadOnlySpan<char> token, bool requireTitleOrDevanagari)
    {
        if (token.IsEmpty) return false;
        bool hasDevanagari = false;
        for (int i = 0; i < token.Length; i++)
        {
            char c = token[i];
            if (IsDevanagari(c))
            {
                hasDevanagari = true;
                continue;
            }
            if (char.IsLetter(c) || c == '\'' || c == '-')
                continue;
            return false;
        }

        if (!requireTitleOrDevanagari)
            return true;

        return hasDevanagari || char.IsUpper(token[0]);
    }

    private static bool IsCapitalizedOrDevanagari(ReadOnlySpan<char> token)
    {
        if (token.IsEmpty) return false;
        if (IsDevanagari(token[0])) return true;
        return char.IsUpper(token[0]) && token.Length >= 2;
    }

    private static bool IsLetterOrDevanagari(char c) => char.IsLetter(c) || IsDevanagari(c);
    private static bool IsDevanagari(char c) => c >= '\u0900' && c <= '\u097F';

    private static void AddUniqueMatch(List<PiiMatch> destination, string text, int index, int length, PiiType type, double confidence)
    {
        for (int i = 0; i < destination.Count; i++)
        {
            var existing = destination[i];
            if (index < existing.Index + existing.Length && index + length > existing.Index)
            {
                if (length > existing.Length)
                {
                    destination[i] = new PiiMatch
                    {
                        RawValue = text.Substring(index, length),
                        Type = type,
                        TypeName = type.ToString(),
                        Confidence = confidence,
                        Index = index,
                        Length = length
                    };
                }
                return;
            }
        }

        destination.Add(new PiiMatch
        {
            RawValue = text.Substring(index, length),
            Type = type,
            TypeName = type.ToString(),
            Confidence = confidence,
            Index = index,
            Length = length
        });
    }
}
