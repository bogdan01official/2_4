import iptc
import json
from enum import Enum
def add_rule_input(src_addr: str, dst_addr: str, src_port: str, dst_port: str,proto: str, allow: bool):
 rule = iptc.Rule()

 if src_addr:
  rule.src = src_addr
 if dst_addr:
  rule.dst = dst_addr
 if proto:
  rule.protocol = proto
  if src_port:
   match = iptc.Match(rule, proto)
   match.sport = src_port
   rule.add_match(match)
  if dst_port:
   match = iptc.Match(rule, proto)
   match.dport = src_port
   rule.add_match(match)
  if allow:
   rule.target = iptc.Target(rule, "ACCEPT")
  else:
   rule.target = iptc.Target(rule, "DROP")

  chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
  chain.insert_rule(rule)
def add_rule_output(src_addr: str, dst_addr: str, src_port: str, dst_port: str, proto: str, allow: bool):
 rule = iptc.Rule()

 if src_addr:
  rule.src = src_addr
 if dst_addr:
  rule.dst = dst_addr
 if proto:
  rule.protocol = proto
  if src_port:
   match = iptc.Match(rule, proto)
   match.sport = src_port
   rule.add_match(match)
  if dst_port:
   match = iptc.Match(rule, proto)
   match.dport = src_port
   rule.add_match(match)
 if allow:
  rule.target = iptc.Target(rule, "ACCEPT")
 else:
  rule.target = iptc.Target(rule, "DROP")

 chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
 chain.insert_rule(rule)
class MainAction(Enum):
 DEFAULT = 0
 ADD_INPUT = 1
 ADD_OUTPUT = 2
 SHOW_RULES = 3
def get_main_action() -> MainAction:
 while True:
  print("Выбирите действие:")
  print("[1] Добавить правило для входящего трафика")
  print("[2] Добавить правило для исходящего трафика")
  print("[3] Показать правила")
  print("[0] Выход")

  choice: int
  try:
   choice = int(input('> '))
  except:
   continue

  if choice == 0:
   return MainAction.DEFAULT
  if choice == 1:
   return MainAction.ADD_INPUT
  if choice == 2:
   return MainAction.ADD_OUTPUT
  if choice == 3:
   return MainAction.SHOW_RULES
class RuleAction(Enum):
 DEFAULT = 0
 ALLOW = 1
 DENY = 2
def get_rule_action() -> RuleAction:
 while True:
  print("Выбирите действие для обрабатываемых пакетов")
  print("[1] Разрешить")
  print("[2] Запретить")
  print("[0] Отмена")

  choice: int
  try:
   choice = int(input('> '))
  except:
   continue

  if choice == 0:
   return RuleAction.DEFAULT
  if choice == 1:
   return RuleAction.ALLOW
  if choice == 2:
   return RuleAction.DENY
def get_string_param(prompt: str):
 print(prompt + " (введите пустую строку для пропуска)")
 return input('> ')
def main():
 stop = False
 while not stop:
  main_action = get_main_action()
  if main_action == MainAction.DEFAULT:
   exit(0)
  if main_action == MainAction.SHOW_RULES:
   data = iptc.easy.dump_table('filter', ipv6=False)
   print(json.dumps(data, indent=2))
   continue

  rule_action = get_rule_action()
  if rule_action == RuleAction.DEFAULT:
   continue

  proto = get_string_param("Введите протокол")
  src_addr = get_string_param("Введите адрес источника")
  dst_addr = get_string_param("Введите адрес назначения")
  src_port = ""
  dst_port = ""
  if proto:
   src_port = get_string_param("Введите порт источника")
   dst_port = get_string_param("Введите порт назначения")

  if main_action == MainAction.ADD_INPUT:
   add_rule_input(src_addr, dst_addr, src_port, dst_port, proto, rule_action == RuleAction.ALLOW)
  if main_action == MainAction.ADD_OUTPUT:
   add_rule_output(src_addr, dst_addr, src_port, dst_port, proto, rule_action == RuleAction.ALLOW)

  print("Правило добавлено!")
if __name__ == "__main__":
 main()














