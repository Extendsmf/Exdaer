from .models import ProcessNode



class ProcessTree:

    def __init__(self):
        self.nodes: dict[ProcessNode] = {}
        self.orphans: dict[str, list[ProcessNode]] = {}

    def add_process(self, node:ProcessNode):
        self.nodes[node.guid] = node
        if node.parent_guid:
            if node.parent_guid in self.nodes:        
                
                parent_proc =  self.nodes.get(node.parent_guid)
                parent_proc.children.append(node)
                node.parent = parent_proc
            else:
                self.orphans.setdefault(node.parent_guid, []).append(node)
            

        if node.guid in self.orphans:
            # Забираем весь список ожидающих детей и сразу удаляем ключ из orphans
            waiting_children = self.orphans.pop(node.guid)
            
            for child in waiting_children:
                child.parent = node
                node.children.append(child)


    def get_process(self, guid: str) -> ProcessNode | None:
        return self.nodes.get(guid)
    

    def get_lineage(self, guid: str) -> list[ProcessNode]:
        node = self.nodes.get(guid)
        if not node:
            return[]
        
        proc_lineage = [node]

        while node.parent:
            node = node.parent
            proc_lineage.append(node)

        return proc_lineage

            