# Library Imports
import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
import dash
import dash_bootstrap_components as dbc
from dash import html, dcc, dash_table
from dash.dependencies import Input, Output

# SIEM Data
reports = pd.read_csv("Dataset 5__Security_Incident_Reports.csv", parse_dates=['report_time'])
reports.category = reports['category'].astype('category')
reports.detected_by = reports.detected_by.astype('category')

#
reports_opened = reports[reports['resolution_status'] != 'Resolved']
data = [go.Table(
    header=dict(values=list(reports_opened),
                fill_color='gold',
                align='center'),
    cells=dict(values=[reports_opened[col] for col in reports_opened.columns],
    fill_color='white',
    align='center'))
]
table_fig = go.Figure(data=data)


# 
rcat = reports['category'].value_counts().reset_index()
rcat_labels = [cat for cat in rcat['category']]
rcat_values = [tot for tot in rcat['count']]
p1_fig = go.Figure(data=[go.Pie(labels=rcat_labels, values=rcat_values, textinfo='label+percent',
                             insidetextorientation='radial'
                            )])

rdetected_by = reports['detected_by'].value_counts().reset_index()
rdetected_labels = [cat for cat in rdetected_by['detected_by']]
rdetected_values = [tot for tot in rdetected_by['count']]

p2_fig = go.Figure(data=[go.Pie(labels=rdetected_labels, values=rdetected_values, textinfo='label+percent',
                             insidetextorientation='radial'
                            )])

#==================================================================================
authlogs = pd.read_csv("Dateset 2__User_Authentication_Logs.csv", parse_dates=['login_timestamp'])
authlogs.rename(columns=dict(login_timestamp='date'),inplace=True)
authlogs['login_status'] = authlogs['login_status'].astype('category')

login_totals = authlogs.username.value_counts()
unpivoted = authlogs.groupby(['username','login_status']).size().reset_index().rename(columns={0:'Count'})
pivoted = unpivoted.pivot(
    columns='login_status',
    index='username',
    values='Count')

successes = [col for col in pivoted['Success']]
fails = [col for col in pivoted['Failure']]
users = [ind for ind in pivoted.index]


success_fail_chart = go.Figure()
success_fail_chart.add_trace(go.Bar(x=[ind for ind in pivoted.index], y=successes, name="Successful Logins",marker_color='green'))
success_fail_chart.add_trace(go.Bar(x=users, y=fails, name="Failed Attempts",marker_color='red'))
success_fail_chart.update_layout(
    barmode='group',
    # title='Login Successes and Failures',
    xaxis_title='Users',
    yaxis_title='Count',
)

failed_authlogs = authlogs[authlogs['login_status'] == 'Failure']
failed_authlogs['geo_location'].value_counts()

geo_location_pie = go.Figure(data=[go.Pie(labels=failed_authlogs['geo_location'], values=failed_authlogs['geo_location'].value_counts(), textinfo='label+percent',
                             insidetextorientation='radial'
                            )])

data2 = pd.DataFrame({
    'geo_location': [
        'Sydney, Australia', 'Cape Town, South Africa', 'Mumbai, India',
        'San Francisco, USA', 'London, UK', 'Berlin, Germany',
        'New York, USA', 'São Paulo, Brazil', 'Tokyo, Japan', 'Toronto, Canada'
    ],
    'count': [75, 67, 63, 59, 55, 49, 46, 46, 46, 42],
    'lat': [-33.8688, -33.9249, 19.0760, 37.7749, 51.5074, 52.5200, 40.7128, -23.5505, 35.6762, 43.6510],
    'lon': [151.2093, 18.4241, 72.8777, -122.4194, -0.1278, 13.4050, -74.0060, -46.6333, 139.6503, -79.3470]
})

# Create the figure
geomap = go.Figure()

# Add scatter_geo trace
geomap.add_trace(go.Scattergeo(
    lon = data2['lon'],
    lat = data2['lat'],
    text = data2['geo_location'] + "<br>Failed Attempts:" + data2['count'].astype(str),
    marker = dict(
        size = data2['count'],
        color = data2['count'],
        colorscale = 'Hot',
        showscale = True,
        line=dict(width=0.5, color='white'),
        sizemode='area',
        sizeref=10.*max(data2['count'])/(100**2),  # Bubble size scaling
        sizemin=4
    )
))

# Set layout
geomap.update_layout(
    # title = 'Geographical Representation of Failed Login Actiivty',
    geo = dict(
        showland = True,
        landcolor = "white",
        showcountries = True,
        countrycolor = "gray",
        projection_type = "natural earth"
    ),
    height=600
)

#==================================================================================
# Create a function to generate a card with a graph
def make_graph_card(title, graph_figure):
    return dbc.Card(
        [
            dbc.CardHeader(html.H4(title, className="card-title")),
            dbc.CardBody(
                [
                    dcc.Graph(figure=graph_figure)
                ]
            ),
        ],
        className="mb-4 shadow"  # Add margin-bottom and shadow for styling
    )

# Function used to create display cards
def make_pay_gap_card(title):
    stats = dbc.Row([
        dbc.Col([
            html.Div("Response Time Stats",className=" border-bottom border-3"),
            html.Div("Average Time"),
            html.Div("Max Time"),
            html.Div("Min Time"),
        ], style={"minWidth": 250}),
        
        dbc.Col([
            html.Div("Stats", className=" border-bottom border-3"),
            html.Div(f"{reports['response_time_minutes'].mean()}"),
            html.Div(f"{reports['response_time_minutes'].max()}"),
            html.Div(f"{reports['response_time_minutes'].min()}"),
        ])
    ], style={"minWidth": 400})

    totals = dbc.Alert(dcc.Markdown(
        f"""
        ** Total Incidents **  
        ### {len(reports['incident_id'])}  
        """,
    ), color="dark")

    mean = dbc.Alert(dcc.Markdown(
        f"""
        ** Open Incidents ** 
        ### {len(reports_opened)}  
        """,
    ), color="dark")

    card =  dbc.Card([
        dbc.CardHeader(html.H2("Incident Stats"), className="text-center"),
        dbc.CardBody([
            dbc.Row([dbc.Col(totals), dbc.Col(mean)], className="text-center"),
            stats
        ])
    ])
    return card
#################################################################################################

# Building SIEM Dashboard Content and Layot for Tab
tab1_siem = dbc.Container(
    [
        html.H1("Everything Organic - SIEM Dahboard", className="my-4 text-center"),
        dbc.Row(
            [
                dbc.Col(make_pay_gap_card("Test"),xl=12),
                dbc.Col(make_graph_card("Threat Categories", p1_fig),md=6),
                dbc.Col(make_graph_card("Security Appliances", p2_fig),md=6),
            ],
            className="mb-4"
        ),
        # You can add more rows and cards as needed
        dbc.Row(
            [
                dbc.Col(make_graph_card("Open Incidents",table_fig),lg=12)
            ],
            className="mb-4"
        )
    ],
    fluid=True,
)

# Building Authentication Dashboard Content and Layout for Tab
tab2_auth = dbc.Container(
    [
        html.H1("Everything Organic - Authentication Activity", className="my-4 text-center"),
        dbc.Row(
            [
                # dbc.Col(make_pay_gap_card("Test"),xl=12),
                dbc.Col(make_graph_card("Failed Logins by Countries", geo_location_pie),md=6)
            ],
            className="mb-4"
        ),
        # You can add more rows and cards as needed
        dbc.Row(
            [
                dbc.Col(make_graph_card("Login Success vs. Failures Overivew", success_fail_chart),xl=10)
            ],
            className="mb-4"
        ),
        dbc.Row(
            [
                dbc.Col(make_graph_card("Geographical Representation of Failed Login Actiivty", geomap),xl=10)
            ],
            className="mb-4"
        )
    ],
    fluid=True,
)
#############################################################################################
# --- Load Web Server Access Logs ---
df_logs = pd.read_csv('Dataset 1__Web_Server_Access_Logs.csv', parse_dates=['timestamp'])
df_logs['hour'] = df_logs['timestamp'].dt.floor('h')
method_counts = df_logs.groupby(['hour', 'http_method']).size().reset_index(name='count')

# Plot: HTTP Method Usage
fig_logs = px.bar(
    method_counts, x='hour', y='count', color='http_method',
    title='HTTP Method Usage Over Time',
    labels={'hour': 'Time (Hour)', 'count': 'Number of Requests'}
)

# Plot: Average Response Time
avg_response_time = df_logs.groupby('hour')['response_time_ms'].mean().reset_index()
fig_response_time = px.line(
    avg_response_time,
    x='hour',
    y='response_time_ms',
    title='Average Response Time Over Time',
    labels={'hour': 'Time (Hour)', 'response_time_ms': 'Avg Response Time (ms)'}
)

# --- Load Network Traffic Summary ---
df_traffic = pd.read_csv('Dataset 4__Network_Traffic_Summary.csv', parse_dates=['sample_time'])
df_traffic['suspicious'] = df_traffic['suspicious_activity'].str.lower() == 'yes'
df_traffic['date'] = df_traffic['sample_time'].dt.date

# Aggregate daily traffic
agg_df = df_traffic.groupby('date')[['inbound_bytes', 'outbound_bytes']].sum().reset_index()
agg_df['date'] = pd.to_datetime(agg_df['date'])
agg_df_long = agg_df.melt(
    id_vars='date',
    value_vars=['inbound_bytes', 'outbound_bytes'],
    var_name='Traffic Type',
    value_name='Bytes'
)

fig_scaled = px.bar(
    agg_df_long,
    x='date',
    y='Bytes',
    color='Traffic Type',
    barmode='group',
    title='Daily Network Traffic: Inbound vs Outbound Bytes',
    labels={'date': 'Date'}
)

fig_scaled.update_layout(
    yaxis=dict(title='Bytes', range=[0, 120000]),
    xaxis=dict(
        range=[pd.to_datetime('2025-06-01'), pd.to_datetime('2025-06-22')],
        tickformat='%b %d',
        tickangle=-45,
        dtick="D1"
    )
)

# Suspicious activity table
suspicious_df = df_traffic[df_traffic['suspicious']][[
    'sample_time', 'protocol', 'source_ip', 'inbound_bytes', 'outbound_bytes'
]]

# --- Styling Definitions ---
FONT_FAMILY = 'Segoe UI, Roboto, Open Sans, sans-serif'

HEADER_STYLE = {
    'fontFamily': FONT_FAMILY,
    'textAlign': 'center',
    'fontSize': '28px',
    'fontWeight': '600',
    'color': '#2c3e50'
}

SUBHEADER_STYLE = {
    'fontFamily': FONT_FAMILY,
    'textAlign': 'center',
    'fontSize': '20px',
    'fontWeight': '500',
    'color': '#34495e',
    'marginBottom': '15px'
}

card_style = {
    'border': '1px solid #dcdcdc',
    'borderRadius': '10px',
    'padding': '20px',
    'boxShadow': '0px 2px 5px rgba(0,0,0,0.05)',
    'marginBottom': '30px',
    'backgroundColor': '#ffffff',
    'fontFamily': FONT_FAMILY
}

color_map = {
    'Adware': 'orange',
    'Malware': 'crimson',
    'Rootkit': 'darkblue',
    'Ransomware': 'purple',
    'Spyware': 'green',
    'Trojan': 'darkred',
    'Worm': 'teal',
}

column_name_map = {
    'alert_id': 'Alert Id',
    'detection_time': 'Detection Time',
    'threat_type': 'Threat Type',
    'severity': 'Severity',
    'affected_file': 'Affected File',
    'remediation_status': 'Remediation Status'
}

#==================================================================================
# --- Read malware threat alerts data ---
df_alerts = pd.read_csv('dataset_3_malware_threat_alerts.csv')
df_alerts['detection_time'] = pd.to_datetime(df_alerts['detection_time'], errors='coerce')
#==================================================================================

app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
#############################################################################################
@app.callback(
    Output('malware-alerts-content', 'children'),
    [Input('date-picker-range-alerts', 'start_date'),
     Input('date-picker-range-alerts', 'end_date')]
)
def update_malware_alerts(start_date, end_date):
    try:
        start_date = pd.to_datetime(start_date)
        end_date = pd.to_datetime(end_date)
    except Exception:
        return html.Div([html.H3("Invalid date range. Please select valid dates.")], style={"color": "red"})

    filtered_df = df_alerts[
        (df_alerts['detection_time'] >= start_date) & (df_alerts['detection_time'] <= end_date)
    ]

    if filtered_df.empty:
        return html.Div([html.H3("No data available for the selected date range.")], style={"color": "blue"})

    threat_counts = filtered_df['threat_type'].value_counts().sort_index()
    bars = [
        go.Bar(
            x=[threat],
            y=[threat_counts[threat]],
            name=threat,
            marker=dict(color=color_map.get(threat, 'gray')),
            text=[threat_counts[threat]],
            textposition='auto'
        )
        for threat in threat_counts.index
    ]

    fig = go.Figure(data=bars, layout=go.Layout(
        title={'text': 'Total Alerts by Threat Type'},
        xaxis=dict(title='Threat Type'),
        yaxis=dict(title='Number of Alerts'),
        barmode='group'
    ))

    datatable = dash_table.DataTable(
        id='datatable-threat-records',
        columns=[
            {"name": column_name_map.get(col, col), "id": col} for col in filtered_df.columns
        ],
        data=filtered_df.to_dict('records'),
        style_table={'overflowX': 'auto'},
        style_cell={
            'textAlign': 'left',
            'padding': '10px',
            'whiteSpace': 'normal',
            'height': 'auto'
        },
        style_header={
            'backgroundColor': 'lightgrey',
            'color': 'black',
            'fontWeight': 'bold',
            'border': '2px solid grey'
        },
        page_size=10,
    )

    return html.Div([
        dcc.Graph(id='bar-chart-threat-totals', figure=fig),
        html.H4('Filtered Records:'),
        datatable
    ])

@app.callback(
    Output('threat-monitoring-content', 'children'),
    [Input('date-picker-range-monitoring', 'start_date'),
     Input('date-picker-range-monitoring', 'end_date')],
)
def update_threat_monitoring(start_date, end_date):
    try:
        start_date = pd.to_datetime(start_date)
        end_date = pd.to_datetime(end_date)
    except Exception:
        return html.Div([html.H3("Invalid date range. Please select valid dates.")], style={"color": "red"})

    filtered_df = df_alerts[
        (df_alerts['detection_time'] >= start_date) & (df_alerts['detection_time'] <= end_date)
    ]

    if filtered_df.empty:
        return html.Div([html.H3("No data available for the selected date range.")], style={"color": "blue"})

    severity_counts = (
        filtered_df
        .groupby([filtered_df['detection_time'].dt.date, 'severity'])
        .size()
        .unstack(fill_value=0)
    )

    severity_levels = ['Critical', 'High', 'Medium', 'Low']
    for severity in severity_levels:
        if severity not in severity_counts.columns:
            severity_counts[severity] = 0
    severity_counts = severity_counts[severity_levels]

    line_traces = [
        go.Scatter(
            x=severity_counts.index,
            y=severity_counts[severity],
            mode='lines+markers',
            name=severity,
            line=dict(shape='linear')
        )
        for severity in severity_levels
    ]

    line_chart = go.Figure(data=line_traces, layout=go.Layout(
        title={'text': 'Severity Levels Over Time'},
        xaxis=dict(title='Date', tickformat='%Y-%m-%d', type='category'),
        yaxis=dict(title='Threat Count'),
        hovermode='x unified',
        legend=dict(title="Severity Levels"),
    ))

    status_counts = filtered_df['remediation_status'].value_counts()
    statuses = ['Resolved', 'Pending', 'Escalated']
    status_data = [status_counts.get(status, 0) for status in statuses]

    pie_chart = go.Figure(data=[
        go.Pie(
            labels=statuses,
            values=status_data,
            hole=0.4,
            textinfo="label+percent",
            hoverinfo="label+value"
        )
    ], layout=go.Layout(
        title={'text': 'Threat Status Distribution', 'x': 0.5, 'xanchor': 'center'},
        showlegend=True
    ))

    return html.Div([
        dcc.Graph(id='line-chart-severity', figure=line_chart),
        dcc.Graph(id='pie-chart-status', figure=pie_chart)
    ])
#############################################################################################
# Malware and Threat Alerts Tab
tab_malware_alerts = dcc.Tab(
    label='Malware and Threat Alerts',
    children=[
        html.Div([
            html.H3("Malware and Threat Alerts Dashboard", style=SUBHEADER_STYLE),
            html.Label('Select Date Range:'),
            dcc.DatePickerRange(
                id='date-picker-range-alerts',
                start_date=str(df_alerts['detection_time'].min().date()),
                end_date=str(df_alerts['detection_time'].max().date()),
                display_format='YYYY-MM-DD',
                style={'margin-left': '10px'}
            ),
            dcc.Loading(
                id='loading-malware-alerts',
                type='default',
                children=html.Div(id='malware-alerts-content')
            )
        ], style={'padding': '20px', 'backgroundColor': '#f4f6f9'})
    ]
)

# Threat Monitoring Tab
tab_threat_monitoring = dcc.Tab(
    label='Threat Monitoring',
    children=[
        html.Div([
            html.H3("Threat Monitoring Dashboard", style=SUBHEADER_STYLE),
            html.Label('Select Date Range:'),
            dcc.DatePickerRange(
                id='date-picker-range-monitoring',
                start_date=str(df_alerts['detection_time'].min().date()),
                end_date=str(df_alerts['detection_time'].max().date()),
                display_format='YYYY-MM-DD',
                style={'margin-left': '10px'}
            ),
            dcc.Loading(
                id='loading-threat-monitoring',
                type='default',
                children=html.Div(id='threat-monitoring-content')
            )
        ], style={'padding': '20px', 'backgroundColor': '#f4f6f9'})
    ]
)
#############################################################################################
tabs = dbc.Tabs(
    [
        dbc.Tab(tab1_siem, label="SIEM Overview"),
        dbc.Tab(tab2_auth, label="Authentication Overview"),
        tab_malware_alerts,
        tab_threat_monitoring,
        dcc.Tab(label='Web Server Activity & Performance', children=[
            html.Div([
                html.Div([
                    html.H3("HTTP Method Activity", style=SUBHEADER_STYLE),
                    dcc.Graph(figure=fig_logs)
                ], style=card_style),

                html.Div([
                    html.H3("Average Response Time", style=SUBHEADER_STYLE),
                    dcc.Graph(figure=fig_response_time)
                ], style=card_style)
            ], style={'padding': '20px', 'backgroundColor': '#f4f6f9'})
        ]),
        dcc.Tab(label='Network Traffic & Threat Monitoring', children=[
            html.Div([
                html.Div([
                    html.H3("Daily Inbound vs Outbound Traffic", style=SUBHEADER_STYLE),
                    dcc.Graph(figure=fig_scaled)
                ], style=card_style),

                html.Div([
                    html.H4("Suspicious Activity Records", style={
                        'fontFamily': FONT_FAMILY,
                        'fontSize': '18px',
                        'fontWeight': '500',
                        'color': '#2c3e50',
                        'marginBottom': '15px'
                    }),

                    dcc.DatePickerRange(
                        id='date-range-picker',
                        min_date_allowed=suspicious_df['sample_time'].min().date(),
                        max_date_allowed=suspicious_df['sample_time'].max().date(),
                        start_date=suspicious_df['sample_time'].min().date(),
                        end_date=suspicious_df['sample_time'].max().date(),
                        display_format='YYYY-MM-DD',
                        style={'marginBottom': '15px'}
                    ),

                    dash_table.DataTable(
                        id='suspicious-table',
                        columns=[{'name': col, 'id': col} for col in suspicious_df.columns],
                        data=suspicious_df.to_dict('records'),
                        style_table={'overflowX': 'auto'},
                        style_cell={
                            'fontFamily': FONT_FAMILY,
                            'textAlign': 'left',
                            'padding': '5px',
                            'minWidth': '100px',
                            'maxWidth': '200px',
                            'whiteSpace': 'normal',
                            'fontSize': '14px'
                        },
                        style_header={
                            'backgroundColor': '#eaeaea',
                            'fontWeight': 'bold',
                            'fontSize': '14px'
                        },
                        page_size=10,
                        filter_action='native',
                        sort_action='native'
                    )
                ], style=card_style)
            ], style={'padding': '20px', 'backgroundColor': '#f4f6f9'})
        ])])

@app.callback(
    Output('suspicious-table', 'data'),
    Input('date-range-picker', 'start_date'),
    Input('date-range-picker', 'end_date')
)
def filter_suspicious_by_date(start_date, end_date):
    if start_date and end_date:
        filtered_df = suspicious_df[
            (suspicious_df['sample_time'] >= pd.to_datetime(start_date)) &
            (suspicious_df['sample_time'] <= pd.to_datetime(end_date) + pd.Timedelta(days=1))
        ]
    else:
        filtered_df = suspicious_df
    return filtered_df.to_dict('records')
#######################################################################

app.layout = tabs

if __name__ == '__main__':
    app.run(debug=True)
