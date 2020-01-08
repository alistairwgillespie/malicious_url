import whois
from datetime import datetime

def creation_date(domain_name):
    """
    Gets creation date of domain
    """
    
    # Get creation date of Domain 
    domain_name = whois.whois(domain_name).creation_date
    
    # Handling exceptions
    if type(domain_name) is list:
        return domain_name[0]
    elif str(domain_name).find('Aug'):
        domain_name = "1996-07-01 00:00:01"
        return domain_name
    elif domain_name == np.nan:
        currentDT = datetime.now()
        domain_name = currentDT.strftime("%Y-%m-%d %H:%M:%S")
        return domain_name
    else:
        return domain_name

def countSpecial(x):
    """
    Counts number of special characters in a string
    """
    new = re.sub('[\w]+' ,'', x)
    return len(new)

def entropy(string):
    """
    Calculates the Shannon entropy of a string
    """

    # Get probability of chars in string
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]

    # Calculate the entropy
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])

    return entropy

from socket import gethostbyname, gaierror

def host_ip(domain):
    """
    Gets Host IP of Domain
    """

    # Get HOST IP     
    try:
        host = gethostbyname(domain)
        return host
    except gaierror:
        return 'missing'
    
import tldextract

def get_domain_parts(df, feature_col):
    """
    Extract domain components
    """
    
    # Extract domain
    df['domain'] = df[feature_col].apply(lambda x: tldextract.extract(x).domain)
    
    # Extract suffix
    df['suffix'] = df[feature_col].apply(lambda x: tldextract.extract(x).suffix)
    
    # Extract suffix
    df['domain_name'] = df[feature_col].apply(lambda x: tldextract.extract(x).registered_domain)
    
    # TODO - Handle null domain and suffix
    
    return df

def get_host_ip(df, domain_col):
    """
    Gets host IP address associated with domain
    """
    
    # Extract Host IP 
    df['host_ip'] = df[domain_col].apply(lambda x: host_ip(x))
    
    # TODO - Handle null hosts
    
    return df

def get_prefix(df, host_col):
    """
    Gets first octet of IP
    """
    
    # Extract prefix, first octet
    df['prefix'] = df[host_col].str.extract('(\d+)\.').astype(float, errors='ignore').astype(str)
    df['prefix'] = df['prefix'].fillna('missing')
    df['prefix'] = df['prefix'].replace('nan', 'missing')
    
    return df

def get_creation_date(df, feature_col):
    """
    Gets creation date of domain
    """
    
    df['domain_creation'] = df[feature_col].apply(lambda x: creation_date(x))

    return df

def get_time_features(df, date_col):
    """
    Calculates days since date.
    """
      
    # Cast date_col to datetime
    df[date_col] = pd.to_datetime(df[date_col], format='%Y-%m-%d %H:%M:%S', errors='coerce')
    
    # Calculate days since date
    df['days_since_' + date_col] = pd.datetime.today().date() - df[date_col].dt.date
    df['days_since_' + date_col] = df['days_since_' + date_col].astype(str).str.extract("(\d+)").astype(float)

    df[date_col + "_day"] = df[date_col].dt.day
    df[date_col + "_month"] = df[date_col].dt.month
    df[date_col + "_year"] = df[date_col].dt.year
    
    return df

def get_domain_entropy(df, feature_col):
    """
    Calculates entropy of a feature for a given data set
    """
    
    # Calculate entropy 
    df['entropy'] = df[feature_col].apply(lambda x: entropy(str(x)))

    return df

def get_number_suffix(df, feature_col):
    """
    Calculates number of suffix in the URL
    """
    
    # Calculates number of suffix in the URL
    df['number_suffix'] = df[feature_col].str.count('\.')
    
    return df

def get_number_digits(df, feature_col):
    """
    Calculates number of numerical characters in a string
    """
    
    # Calculates number of digits
    df['number_digits'] = df[feature_col].str.count('[0-9]')
    
    return df

def get_percent_digits(df):
    """
    Calculates percentage of string is a digit
    """
    
    # Calculate percentage
    df['digits_percentage'] = (df['number_digits']/df['string_length'])*100
    
    return df

def get_string_length(df, feature_col):
    """
    Calculates length of string
    """

    # Calculates length of string
    df['string_length'] = df[feature_col].str.len()
    
    return df

def get_specials(df, feature_col):
    """
    Calculates number of special characters in string
    """
    
    # Count of special characters
    df['specials'] = df[feature_col].apply(lambda x: countSpecial(str(x)))
   
    return df

def get_iana_designations(df, iana, prefix_col):
    """
    Merges data sets on the prefix i.e. first octect of the IPv4 address
    """

    # Enrich sample with IPv4 Registry data
    df = df.merge(iana, on=prefix_col, how='left')

    # Clean prefix and drop unneeded columns
    df['prefix'] = df['prefix'].astype(str)
    df['designation'] = df['designation'].fillna('missing')
    df.rename(columns={ 'status [1]': 'status'}, inplace=True)
    df.drop(['note'], axis=1, inplace=True)

    return df