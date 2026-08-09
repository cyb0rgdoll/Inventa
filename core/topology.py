"""
Network Topology Mapping Module
Generate network topology visualizations from discovered assets
"""

import json
from pathlib import Path
from typing import List, Dict
from collections import defaultdict


def map_topology(assets: List[Dict], out_dir: Path) -> Dict:
    """
    Generate network topology map from discovered assets
    
    Args:
        assets: List of asset dictionaries
        out_dir: Output directory for topology files
    
    Returns:
        Topology data structure
    """
    topology = {
        'nodes': [],
        'edges': [],
        'subnets': defaultdict(list)
    }
    
    # Build nodes from assets
    for idx, asset in enumerate(assets):
        ip = asset.get('ip')
        if not ip:
            continue
        
        # Determine subnet
        subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
        
        node = {
            'id': idx,
            'ip': ip,
            'hostname': asset.get('hostname'),
            'asset_type': asset.get('asset_type', 'Unknown'),
            'subnet': subnet,
            'services': asset.get('services', []),
            'os': asset.get('os')
        }
        
        topology['nodes'].append(node)
        topology['subnets'][subnet].append(idx)
    
    # Infer connections based on service dependencies
    # This is heuristic-based - real topology would require traceroute/ARP
    for i, node in enumerate(topology['nodes']):
        services = node.get('services', [])
        
        # Connect workstations to domain controllers
        if 'ldap' in services or node.get('asset_type') == 'Domain Controller':
            # This is a DC - connect all workstations to it
            for j, other_node in enumerate(topology['nodes']):
                if i != j and 'Workstation' in other_node.get('asset_type', ''):
                    topology['edges'].append({
                        'source': j,
                        'target': i,
                        'type': 'authentication'
                    })
        
        # Connect web servers to database servers (same subnet)
        if node.get('asset_type') == 'Web Server':
            for j, other_node in enumerate(topology['nodes']):
                if i != j and other_node.get('asset_type') == 'Database Server':
                    if node['subnet'] == other_node['subnet']:
                        topology['edges'].append({
                            'source': i,
                            'target': j,
                            'type': 'data'
                        })
    
    # Generate visualization files
    generate_topology_html(topology, out_dir)
    generate_topology_json(topology, out_dir)
    
    return topology


def generate_topology_html(topology: Dict, out_dir: Path):
    """Generate an interactive HTML topology visualization"""
    
    html_template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Inventa Tool - Current Network Topology</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{ background: #0d1117; color: #c9d1d9; font-family: monospace; margin: 20px; }}
        h1 {{ color: #58a6ff; }}
        #topology {{ border: 1px solid #30363d; background: #161b22; }}
        .node {{ cursor: pointer; }}
        .node circle {{ stroke: #58a6ff; stroke-width: 2px; }}
        .link {{ stroke: #484f58; stroke-width: 1.5px; }}
        .tooltip {{ position: absolute; background: #1c2128; border: 1px solid #30363d; 
                    padding: 8px; border-radius: 4px; pointer-events: none; display: none; }}
    </style>
</head>
<body>
    <h1>Inventa | Current Network Topology 🌐</h1>
    <div id="stats">
        <p>Nodes: {node_count} | Edges: {edge_count} | Subnets: {subnet_count}</p>
    </div>
    <svg id="topology" width="1200" height="800"></svg>
    <div id="tooltip" class="tooltip"></div>
    
    <script>
        const data = {topology_json};
        
        const svg = d3.select("#topology");
        const width = 1200;
        const height = 800;
        
        const simulation = d3.forceSimulation(data.nodes)
            .force("link", d3.forceLink(data.edges).id(d => d.id).distance(150))
            .force("charge", d3.forceManyBody().strength(-400))
            .force("center", d3.forceCenter(width / 2, height / 2));
        
        const link = svg.append("g")
            .selectAll("line")
            .data(data.edges)
            .enter().append("line")
            .attr("class", "link");
        
        const node = svg.append("g")
            .selectAll("g")
            .data(data.nodes)
            .enter().append("g")
            .attr("class", "node")
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));
        
        node.append("circle")
            .attr("r", 8)
            .attr("fill", d => getNodeColor(d.asset_type));
        
        node.append("text")
            .attr("dx", 12)
            .attr("dy", 4)
            .text(d => d.hostname || d.ip)
            .style("fill", "#c9d1d9")
            .style("font-size", "10px");
        
        node.on("mouseover", function(event, d) {{
            d3.select("#tooltip")
                .style("display", "block")
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 10) + "px")
                .html(`<strong>${{d.ip}}</strong><br/>
                       Type: ${{d.asset_type}}<br/>
                       OS: ${{d.os || 'Unknown'}}<br/>
                       Services: ${{d.services.join(', ')}}`);
        }})
        .on("mouseout", function() {{
            d3.select("#tooltip").style("display", "none");
        }});
        
        simulation.on("tick", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
            
            node.attr("transform", d => `translate(${{d.x}},${{d.y}})`);
        }});
        
        function getNodeColor(type) {{
            const colors = {{
                'Web Server': '#58a6ff',
                'Database Server': '#f85149',
                'Domain Controller': '#a371f7',
                'Mail Server': '#56d364',
                'Workstation': '#d29922',
                'Network Device': '#8b949e'
            }};
            return colors[type] || '#6e7681';
        }}
        
        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}
        
        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}
        
        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}
    </script>
</body>
</html>
"""
    
    html_output = html_template.format(
        node_count=len(topology['nodes']),
        edge_count=len(topology['edges']),
        subnet_count=len(topology['subnets']),
        topology_json=json.dumps(topology)
    )
    
    output_path = out_dir / "network_topology.html"
    with open(output_path, 'w') as f:
        f.write(html_output)
    
    print(f"  [✓] Topology visualization: {output_path}")


def generate_topology_json(topology: Dict, out_dir: Path):
    """Generate topology data as JSON for external processing"""
    
    output_path = out_dir / "network_topology.json"
    with open(output_path, 'w') as f:
        json.dump(topology, f, indent=2)
    
    print(f"  [✓] Topology JSON: {output_path}")
