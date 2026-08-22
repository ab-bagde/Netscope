recent_reports = []

def add_recent_report(report):
    global recent_reports
    recent_reports.insert(0, report)
    recent_reports = recent_reports[:5]

def load_recent_reports():
    return recent_reports


def clear_list():
    global recent_reports
    recent_reports.clear()