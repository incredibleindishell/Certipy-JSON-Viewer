from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import json
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

DATABASE = 'certipy_viewer.db'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_name TEXT NOT NULL UNIQUE,
                json_data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_project():
    if request.method == 'POST':
        project_name = request.form.get('project_name', '').strip()
        
        if not project_name:
            flash('Project name is required', 'error')
            return redirect(url_for('upload_project'))
        
        if 'json_file' not in request.files:
            flash('No file uploaded', 'error')
            return redirect(url_for('upload_project'))
        
        file = request.files['json_file']
        
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('upload_project'))
        
        if not file.filename.endswith('.json'):
            flash('Only JSON files are allowed', 'error')
            return redirect(url_for('upload_project'))
        
        try:
            # Read and validate JSON
            json_content = file.read().decode('utf-8')
            json_data = json.loads(json_content)
            
            # Store in database
            with get_db() as conn:
                conn.execute(
                    'INSERT INTO projects (project_name, json_data) VALUES (?, ?)',
                    (project_name, json_content)
                )
                conn.commit()
            
            flash(f'Project "{project_name}" uploaded successfully!', 'success')
            return redirect(url_for('view_projects'))
            
        except json.JSONDecodeError:
            flash('Invalid JSON file format', 'error')
        except sqlite3.IntegrityError:
            flash(f'Project "{project_name}" already exists', 'error')
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('upload_project.html')

@app.route('/projects')
def view_projects():
    with get_db() as conn:
        projects = conn.execute(
            'SELECT project_name, created_at FROM projects ORDER BY created_at DESC'
        ).fetchall()
    
    return render_template('view_projects.html', projects=projects)

@app.route('/view/<project_name>')
def view_project(project_name):
    with get_db() as conn:
        project = conn.execute(
            'SELECT * FROM projects WHERE project_name = ?',
            (project_name,)
        ).fetchone()
    
    if not project:
        flash('Project not found', 'error')
        return redirect(url_for('view_projects'))
    
    try:
        json_data = json.loads(project['json_data'])
        rendered_output = render_certipy_data(json_data)
        
        return render_template('display_project.html', 
                             project_name=project_name,
                             output=rendered_output,
                             created_at=project['created_at'])
    except Exception as e:
        flash(f'Error parsing project data: {str(e)}', 'error')
        return redirect(url_for('view_projects'))

@app.route('/delete/<project_name>', methods=['POST'])
def delete_project(project_name):
    try:
        with get_db() as conn:
            conn.execute('DELETE FROM projects WHERE project_name = ?', (project_name,))
            conn.commit()
        flash(f'Project "{project_name}" deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting project: {str(e)}', 'error')
    
    return redirect(url_for('view_projects'))

def detect_additional_vulnerabilities(template_data):
    """
    Detect additional ESC vulnerabilities that may not be in Certipy's output
    because they weren't exploitable by the current user
    """
    additional_vulns = {}
    
    # Get template properties
    enrollee_supplies = template_data.get('Enrollee Supplies Subject', False)
    client_auth = template_data.get('Client Authentication', False)
    enrollment_agent = template_data.get('Enrollment Agent', False)
    any_purpose = template_data.get('Any Purpose', False)
    requires_approval = template_data.get('Requires Manager Approval', False)
    schema_version = template_data.get('Schema Version', 2)
    
    # Check Certificate Name Flag for numeric value 1 (ENROLLEE_SUPPLIES_SUBJECT)
    cert_name_flags = template_data.get('Certificate Name Flag', [])
    if isinstance(cert_name_flags, list):
        if 1 in cert_name_flags or 'ENROLLEE_SUPPLIES_SUBJECT' in str(cert_name_flags):
            enrollee_supplies = True
    
    # Check Enrollment Flags for NO_SECURITY_EXTENSION
    enrollment_flags = template_data.get('Enrollment Flag', [])
    has_no_security_extension = False
    if isinstance(enrollment_flags, list):
        # Check for numeric flag 4096 (0x1000) or string flag
        if 4096 in enrollment_flags or any('NO_SECURITY_EXTENSION' in str(f) for f in enrollment_flags):
            has_no_security_extension = True
    
    # Get enrollment permissions
    permissions = template_data.get('Permissions', {})
    enrollment_perms = permissions.get('Enrollment Permissions', {})
    enrollment_rights = enrollment_perms.get('Enrollment Rights', [])
    
    # Check if low-privilege groups can enroll
    low_priv_groups = []
    for principal in enrollment_rights:
        principal_str = str(principal)
        if any(x in principal_str for x in ['Domain Users', 'Domain Computers', 'Authenticated Users']):
            low_priv_groups.append(principal_str)
    
    has_low_priv_enrollment = len(low_priv_groups) > 0
    
    # Get Object Control Permissions
    obj_control_perms = permissions.get('Object Control Permissions', {})
    
    # Check for vulnerable ACLs (ESC4)
    has_vulnerable_acl = False
    for perm_type in ['Write Owner Principals', 'Write Dacl Principals', 'Write Property Enroll']:
        if perm_type in obj_control_perms:
            principals = obj_control_perms[perm_type]
            if isinstance(principals, list):
                for principal in principals:
                    principal_str = str(principal)
                    if any(x in principal_str for x in ['Domain Users', 'Domain Computers', 'Authenticated Users']):
                        has_vulnerable_acl = True
                        break
    
    # ESC1: Enrollee Supplies Subject + Client Auth + No Manager Approval + Low-Priv Enrollment
    if enrollee_supplies and client_auth and not requires_approval and has_low_priv_enrollment:
        if 'ESC1' not in template_data.get('[!] Vulnerabilities', {}):
            additional_vulns['ESC1'] = f"{', '.join(low_priv_groups)} can enroll with arbitrary subject name and Client Auth EKU"
    
    # ESC2: Any Purpose EKU + No Manager Approval + Low-Priv Enrollment
    if any_purpose and not requires_approval and has_low_priv_enrollment:
        if 'ESC2' not in template_data.get('[!] Vulnerabilities', {}):
            additional_vulns['ESC2'] = f"{', '.join(low_priv_groups)} can request certificates for any purpose (Any Purpose EKU)"
    
    # ESC3: Enrollment Agent + Low-Priv Enrollment
    if enrollment_agent and has_low_priv_enrollment:
        if 'ESC3' not in template_data.get('[!] Vulnerabilities', {}):
            additional_vulns['ESC3'] = f"{', '.join(low_priv_groups)} can enroll on behalf of other users (Certificate Request Agent EKU)"
    
    # ESC4: Vulnerable ACL (Write permissions)
    if has_vulnerable_acl:
        if 'ESC4' not in template_data.get('[!] Vulnerabilities', {}):
            additional_vulns['ESC4'] = "Low-privileged users have dangerous write permissions on this template"
    
    # ESC9: No Security Extension + Enrollee Supplies Subject + Low-Priv Enrollment
    if has_no_security_extension and enrollee_supplies and has_low_priv_enrollment:
        if 'ESC9' not in template_data.get('[!] Vulnerabilities', {}):
            additional_vulns['ESC9'] = f"{', '.join(low_priv_groups)} can exploit with enrollee-supplied subject and NO_SECURITY_EXTENSION (Schema v2)"
    
    # ESC15: Schema Version 1 + Enrollee Supplies Subject + Client Auth + Low-Priv Enrollment
    if schema_version == 1 and enrollee_supplies and client_auth and has_low_priv_enrollment and not requires_approval:
        if 'ESC15' not in template_data.get('[!] Vulnerabilities', {}):
            additional_vulns['ESC15'] = f"{', '.join(low_priv_groups)} can exploit with Schema v1 and enrollee-supplied subject"
    
    # ESC17: Schema Version 1 or 2 with specific conditions
    # ESC17 is similar to ESC15 but works with both schema v1 and v2
    if schema_version in [2] and enrollee_supplies and client_auth and has_low_priv_enrollment and not requires_approval:
        # Check if this is actually ESC16 (not already caught by ESC1 or ESC15)
        if 'ESC17' not in template_data.get('[!] Vulnerabilities', {}):
            if enrollment_agent and any_purpose:  # ESC17 specific: combination of multiple dangerous settings
                additional_vulns['ESC17'] = f"{', '.join(low_priv_groups)} can exploit with Schema v{schema_version}, enrollee-supplied subject, and multiple dangerous EKUs"
    
    return additional_vulns

def render_ca_table(data):
    """Render a compact Certificate Authorities summary table"""
    cas = data.get('Certificate Authorities', {})
    if not cas:
        return ''

    out = []
    out.append('<font color="#00ff00"><b>Certificate Authorities</b></font><br/>')
    out.append('<table width="100%" border="1" cellpadding="8" cellspacing="0" style="font-size:11px; margin-bottom:10px;">')
    out.append('<tr style="background-color:#333;">')
    out.append('<th width="3%"><font color="#ff9933">#</font></th>')
    out.append('<th width="18%"><font color="#ff9933">CA Name</font></th>')
    out.append('<th width="22%"><font color="#ff9933">DNS Name</font></th>')
    out.append('<th width="8%"><font color="#ff9933">HTTP</font></th>')
    out.append('<th width="8%"><font color="#ff9933">HTTPS</font></th>')
    out.append('<th width="10%"><font color="#ff9933">Channel Binding</font></th>')
    out.append('<th width="31%"><font color="#ff9933">Vulnerabilities</font></th>')
    out.append('</tr>')

    for idx, (_, ca_data) in enumerate(cas.items(), start=1):
        ca_name   = ca_data.get('CA Name', 'N/A')
        dns_name  = ca_data.get('DNS Name', 'N/A')

        # Web Enrollment
        web = ca_data.get('Web Enrollment', {})
        http_enabled      = web.get('http', {}).get('enabled', False)  if isinstance(web, dict) else False
        https_enabled     = web.get('https', {}).get('enabled', False) if isinstance(web, dict) else False
        channel_binding   = web.get('https', {}).get('channel_binding', False) if isinstance(web, dict) else False

        def yn(val, danger_if_true=False, danger_if_false=False):
            if val:
                color = '#ff6666' if danger_if_true else '#00ff00'
                return f'<font color="{color}">Yes</font>'
            else:
                color = '#ff6666' if danger_if_false else '#00ff00'
                return f'<font color="{color}">No</font>'

        # HTTP enabled is a warning (ESC8 risk)
        http_cell    = yn(http_enabled,    danger_if_true=True)
        # HTTPS alone is fine
        https_cell   = yn(https_enabled)
        # Channel Binding disabled is a risk
        cb_cell      = yn(channel_binding, danger_if_false=True)

        # Vulnerabilities
        vulns = ca_data.get('[!] Vulnerabilities', {})
        if vulns:
            vuln_parts = []
            for esc, desc in vulns.items():
                vuln_parts.append(f'<font color="#ff6666"><b>{escape_html(esc)}:</b> {escape_html(str(desc))}</font>')
            vuln_cell = '<br/>'.join(vuln_parts)
        else:
            vuln_cell = '<font color="#00ff00">No Known Issues</font>'

        out.append('<tr>')
        out.append(f'<td><font color="#ff9933"><b>{idx}</b></font></td>')
        out.append(f'<td><font color="#ff9933">{escape_html(ca_name)}</font></td>')
        out.append(f'<td><font color="#ffffff">{escape_html(dns_name)}</font></td>')
        out.append(f'<td>{http_cell}</td>')
        out.append(f'<td>{https_cell}</td>')
        out.append(f'<td>{cb_cell}</td>')
        out.append(f'<td>{vuln_cell}</td>')
        out.append('</tr>')

    out.append('</table>')
    return ''.join(out)


def render_certipy_data(data):
    """Render Certipy JSON data as HTML"""
    output = []
    
    output.append('<div class="output">')
    
    # Always render the CA summary table first if CA data is present
    if 'Certificate Authorities' in data:
        output.append(render_ca_table(data))

    # Check if this is certificate templates data
    if 'Certificate Templates' in data:
        templates = data['Certificate Templates']
        
        output.append('<font color="#00ff00"><b>Certificate Templates Analysis</b></font><br/>')
        
        
        # Sort templates: Enabled+Vulnerable first, then Enabled+Safe, then Disabled
        def sort_key(item):
            _, tdata = item
            enabled = tdata.get('Enabled', True)
            certipy_vulns = tdata.get('[!] Vulnerabilities', {})
            additional = detect_additional_vulnerabilities(tdata)
            is_vulnerable = bool(certipy_vulns) or bool(additional)
            name = tdata.get('Template Name', item[0])
            # (not enabled, not vulnerable, name) - lowest tuple sorts first
            return (not enabled, not is_vulnerable, name)

        sorted_templates = sorted(templates.items(), key=sort_key)
        
        # Render templates table
        output.append('<table width="100%" border="1" cellpadding="8" cellspacing="0" style="font-size:11px;">')
        output.append('<tr style="background-color:#333;">')
        output.append('<th width="3%"><font color="#ff9933">#</font></th>')
        output.append('<th width="12%"><font color="#ff9933">Template Name (CN)</font></th>')
        output.append('<th width="10%"><font color="#ff9933">Display Name</font></th>')
        output.append('<th width="8%"><font color="#ff9933">Schema Version</font></th>')
        output.append('<th width="6%"><font color="#ff9933">Published</font></th>')
        output.append('<th width="12%"><font color="#ff9933">Vulnerabilities</font></th>')
        output.append('<th width="49%"><font color="#ff9933">Details</font></th>')
        output.append('</tr>')
        
        row_num = 1
        for dict_key, template_data in sorted_templates:
            # Get vulnerabilities from the JSON
            vulnerabilities = template_data.get('[!] Vulnerabilities', {})
            
            # Detect additional vulnerabilities
            additional_vulns = detect_additional_vulnerabilities(template_data)
            
            # Merge vulnerabilities
            all_vulns = dict(vulnerabilities)
            all_vulns.update(additional_vulns)
            
            vuln_list = list(all_vulns.keys()) if all_vulns else []
            
            vuln_color = '#ff6666' if vuln_list else '#00ff00'
            vuln_text = ', '.join(vuln_list) if vuln_list else 'No Known Issues'
            vuln_icon = '✗' if vuln_list else '✓'
            
            enabled = template_data.get('Enabled', True)
            enabled_color = '#00ff00' if enabled else '#ff6666'
            enabled_text = 'YES' if enabled else 'NO'
            enabled_icon = '✓' if enabled else '✗'
            
            # Use 'Template Name' field from JSON if available, otherwise use dict key
            template_name = template_data.get('Template Name', dict_key)
            # Use 'Display Name' if available, otherwise use template_name
            display_name = template_data.get('Display Name', template_name)
            schema_version = template_data.get('Schema Version', 'N/A')
            
            output.append('<tr>')
            output.append(f'<td><font color="#ff9933"><b>{row_num}</b></font></td>')
            output.append(f'<td><font color="#ff9933">{escape_html(str(template_name))}</font></td>')
            output.append(f'<td><font color="#ffffff">{escape_html(str(display_name))}</font></td>')
            output.append(f'<td><font color="#ffffff">{escape_html(str(schema_version))}</font></td>')
            output.append(f'<td><font color="{enabled_color}">{enabled_icon} {enabled_text}</font></td>')
            output.append(f'<td><font color="{vuln_color}">{vuln_icon} {escape_html(vuln_text)}</font></td>')
            output.append(f'<td style="text-align:left;">')
            output.append(render_template_details_inline(template_data, additional_vulns))
            output.append('</td>')
            output.append('</tr>')
            
            row_num += 1
        
        output.append('</table>')
    
    # Generic JSON viewer for other data types
    else:
        output.append('<font color="#ffff00">Certificate Data:</font><br/><br/>')
        output.append('<pre style="color:#00ff00; background-color:#0a0a0a; padding:10px; border:1px solid #333; font-size:10px;">')
        output.append(escape_html(json.dumps(data, indent=2)))
        output.append('</pre>')
    
    output.append('</div>')
    return ''.join(output)

def render_template_details_inline(template_data, additional_vulns=None):
    """Render inline template details in compact format matching the screenshot"""
    details = []
    
    if additional_vulns is None:
        additional_vulns = {}
    
    # Core Settings Section
    details.append('<font color="#ffffff"><b>Core Settings:</b></font><br/>')
    
    # Enrollee Supplies Subject
    enrollee_supplies = template_data.get('Enrollee Supplies Subject', False)
    enrollee_color = '#00ff00' if enrollee_supplies else '#ffffff'
    details.append(f'&nbsp;&nbsp;<b>Enrollee Supplies Subject:</b> <font color="{enrollee_color}">{str(enrollee_supplies)}</font><br/>')
    
    # Subject Name Flags - Handle both numeric values and string flags
    if 'Certificate Name Flag' in template_data:
        flags = template_data['Certificate Name Flag']
        if isinstance(flags, list) and flags:
            # Check if numeric or string flags
            if all(isinstance(f, int) for f in flags):
                # Numeric flags - check if it's 1 (ENROLLEE_SUPPLIES_SUBJECT)
                if 1 in flags:
                    details.append('&nbsp;&nbsp;<b>Subject Name Flags:</b> ENROLLEE_SUPPLIES_SUBJECT<br/>')
                else:
                    details.append(f'&nbsp;&nbsp;<b>Subject Name Flags:</b> {", ".join([str(f) for f in flags])}<br/>')
            else:
                # String flags
                flag_names = []
                for flag in flags:
                    flag_str = str(flag)
                    if 'ENROLLEE_SUPPLIES_SUBJECT' in flag_str or flag == 1:
                        flag_names.append('ENROLLEE_SUPPLIES_SUBJECT')
                    else:
                        flag_names.append(flag_str)
                if flag_names:
                    details.append(f'&nbsp;&nbsp;<b>Subject Name Flags:</b> {", ".join(flag_names)}<br/>')
    elif enrollee_supplies:
        # If Enrollee Supplies Subject is true but no Certificate Name Flag, show it
        details.append('&nbsp;&nbsp;<b>Subject Name Flags:</b> ENROLLEE_SUPPLIES_SUBJECT<br/>')
    
    # Client Authentication
    client_auth = template_data.get('Client Authentication', False)
    client_color = '#00ff00' if client_auth else '#ffffff'
    details.append(f'&nbsp;&nbsp;<b>Client Authentication:</b> <font color="{client_color}">{str(client_auth)}</font><br/>')
    
    # Enrollment Agent
    enrollment_agent = template_data.get('Enrollment Agent', False)
    agent_color = '#00ff00' if enrollment_agent else '#ffffff'
    details.append(f'&nbsp;&nbsp;<b>Enrollment Agent:</b> <font color="{agent_color}">{str(enrollment_agent)}</font><br/>')
    
    # Any Purpose
    any_purpose = template_data.get('Any Purpose', False)
    purpose_color = '#00ff00' if any_purpose else '#ffffff'
    details.append(f'&nbsp;&nbsp;<b>Any Purpose:</b> <font color="{purpose_color}">{str(any_purpose)}</font><br/>')
    
    # Requires Manager Approval
    requires_approval = template_data.get('Requires Manager Approval', False)
    approval_color = '#ffffff'
    details.append(f'&nbsp;&nbsp;<b>Requires Manager Approval:</b> <font color="{approval_color}">{str(requires_approval)}</font><br/>')
    
    # Authorized Signatures
    auth_sig = template_data.get('Authorized Signatures Required', 0)
    details.append(f'&nbsp;&nbsp;<b>Authorized Signatures:</b> {auth_sig}<br/>')
    
    # Validity Period
    if 'Validity Period' in template_data:
        details.append(f'&nbsp;&nbsp;<b>Validity Period:</b> {escape_html(str(template_data["Validity Period"]))}<br/>')
    
    # Extended Key Usage
    if 'Extended Key Usage' in template_data:
        ekus = template_data['Extended Key Usage']
        if isinstance(ekus, list) and ekus:
            details.append('<br/><font color="#ffffff"><b>Extended Key Usage:</b></font><br/>')
            for eku in ekus:
                eku_str = str(eku)
                # Color code specific EKUs
                if 'Certificate Request Agent' in eku_str:
                    eku_color = '#00ff00'
                elif 'Any Purpose' in eku_str:
                    eku_color = '#00ff00'
                else:
                    eku_color = '#ffffff'
                details.append(f'&nbsp;&nbsp;<font color="{eku_color}">• {escape_html(eku_str)}</font><br/>')
    
    # Permissions Section
    details.append('<br/><font color="#ffffff"><b>Permissions:</b></font><br/>')
    
    if 'Permissions' in template_data:
        permissions = template_data['Permissions']
        
        # Enrollment Permissions
        if 'Enrollment Permissions' in permissions:
            enroll_perms = permissions['Enrollment Permissions']
            
            if 'Enrollment Rights' in enroll_perms:
                details.append('&nbsp;&nbsp;<font color="#ffff00"><b>Enrollment Permissions:</b></font><br/>')
                details.append('&nbsp;&nbsp;<b>Enrollment Rights:</b><br/>')
                
                enrollment_rights = enroll_perms['Enrollment Rights']
                low_priv_enrollers = []
                
                for principal in enrollment_rights:
                    principal_str = str(principal)
                    # Check if it's a low-privilege group
                    is_low_priv = any(x in principal_str for x in ['Domain Users', 'Domain Computers', 'Authenticated Users'])
                    
                    if is_low_priv:
                        low_priv_enrollers.append(principal_str)
                        details.append(f'&nbsp;&nbsp;&nbsp;&nbsp;<font color="#00ff00">• {escape_html(principal_str)}</font><br/>')
                    else:
                        details.append(f'&nbsp;&nbsp;&nbsp;&nbsp;<font color="#00ff00">• {escape_html(principal_str)}</font><br/>')
                
                # Show Low Privilege Enrollers summary
                if low_priv_enrollers:
                    details.append(f'&nbsp;&nbsp;&nbsp;&nbsp;<font color="#ff9933">• <b>Low Privilege Enrollers:</b> {escape_html(", ".join(low_priv_enrollers))}</font><br/>')
        
        # Object Control Permissions
        if 'Object Control Permissions' in permissions:
            obj_perms = permissions['Object Control Permissions']
            details.append('&nbsp;&nbsp;<font color="#ffff00"><b>Object Control Permissions:</b></font><br/>')
            
            if 'Owner' in obj_perms:
                details.append(f'&nbsp;&nbsp;<font color="#00ff00"><b>Owner</b></font><br/>')
                details.append(f'&nbsp;&nbsp;&nbsp;&nbsp;<font color="#00ff00">• {escape_html(str(obj_perms["Owner"]))}</font><br/>')
            
            permission_types = [
                ('Full Control Principals', 'Full Control Principals'),
                ('Write Owner Principals', 'Write Owner Principals'),
                ('Write Dacl Principals', 'Write Dacl Principals'),
                ('Write Property Enroll', 'Write Property Enroll')
            ]
            
            for perm_key, perm_label in permission_types:
                if perm_key in obj_perms:
                    perms_list = obj_perms[perm_key]
                    if perms_list:
                        details.append(f'&nbsp;&nbsp;<font color="#00ff00"><b>{perm_label}</b></font><br/>')
                        if isinstance(perms_list, list):
                            for principal in perms_list:
                                details.append(f'&nbsp;&nbsp;&nbsp;&nbsp;<font color="#00ff00">• {escape_html(str(principal))}</font><br/>')
                        else:
                            details.append(f'&nbsp;&nbsp;&nbsp;&nbsp;<font color="#00ff00">• {escape_html(str(perms_list))}</font><br/>')
    
    # Vulnerability Details Section
    # Merge Certipy vulnerabilities with our detected ones
    certipy_vulns = template_data.get('[!] Vulnerabilities', {})
    all_vulnerabilities = dict(certipy_vulns)
    all_vulnerabilities.update(additional_vulns)
    
    user_enrollers = template_data.get('[+] User Enrollable Principals', [])
    
    if all_vulnerabilities:
        details.append('<br/><font color="#ff6666">🚨 <b>VULNERABILITY DETAILS:</b></font><br/>')
        
        for esc_name, esc_description in all_vulnerabilities.items():
            # Mark if this was detected by our analysis (not in Certipy's output)
            source_tag = ""
            if esc_name in additional_vulns:
                source_tag = " [Detected by Analysis]"
            
            # Format the vulnerability
            details.append(f'<font color="#ff6666">• <b>{escape_html(esc_name)}{source_tag}:</b> {escape_html(str(esc_description))}</font><br/>')
        
        # Show who can exploit (from Certipy's analysis)
        if user_enrollers:
            exploiters = [escape_html(str(e)) for e in user_enrollers]
            details.append(f'<font color="#ff6666">• <b>Exploitable by (Certipy):</b> {", ".join(exploiters)}</font><br/>')
    
    return ''.join(details)

def render_ca_details(ca_key, ca_data):
    """Render CA certificate details"""
    details = []
    
    # Use 'CA Name' from data if available, otherwise use the key
    ca_name = ca_data.get('CA Name', ca_key)
    
    details.append('<div style="margin:10px; padding:10px; background-color:#0a0a0a; border:1px solid #333; font-size:11px;">')
    details.append(f'<font color="#ffff00"><b>Certificate Authority: {escape_html(str(ca_name))}</b></font><br/><br/>')
    
    for key, value in ca_data.items():
        if key in ['[!] Vulnerabilities', '[+] User Enrollable Principals']:
            continue  # Handle these separately
            
        if isinstance(value, dict):
            details.append(f'<b>{escape_html(str(key))}:</b><br/>')
            for subkey, subvalue in value.items():
                details.append(f'&nbsp;&nbsp;<font color="#00ff00">{escape_html(str(subkey))}:</font> {escape_html(str(subvalue))}<br/>')
        elif isinstance(value, list):
            details.append(f'<b>{escape_html(str(key))}:</b><br/>')
            for item in value:
                details.append(f'&nbsp;&nbsp;• {escape_html(str(item))}<br/>')
        else:
            details.append(f'<b>{escape_html(str(key))}:</b> <font color="#00ff00">{escape_html(str(value))}</font><br/>')
    
    # CA Vulnerabilities
    if '[!] Vulnerabilities' in ca_data:
        vulnerabilities = ca_data['[!] Vulnerabilities']
        if vulnerabilities:
            details.append('<br/><font color="#ff6666">🚨 <b>CA VULNERABILITIES:</b></font><br/>')
            for vuln_name, vuln_desc in vulnerabilities.items():
                details.append(f'<font color="#ff6666">• <b>{escape_html(vuln_name)}:</b> {escape_html(str(vuln_desc))}</font><br/>')
    
    details.append('</div><br/>')
    
    return ''.join(details)

def escape_html(text):
    """Escape HTML special characters"""
    if text is None:
        return ''
    return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='127.0.0.1', port=8000)
