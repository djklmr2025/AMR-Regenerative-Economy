import json

class AMRSimulator:
    def __init__(self, num_agents=100, agent_basal_cost=10):
        self.pillars = {
            "p1_energy": 1000,
            "p2_water": 1000,
            "p3_agriculture": 1000,
            "p4_waste": 1000,
            "p5_education": 1000,
            "p6_health": 1000,
            "p7_infrastructure": 1000,
            "p8_technology": 1000,
            "p9_culture": 1000,
            "p10_reserves": 1000
        }
        self.amr_reserves = 10000
        self.amr_circulating = 5000
        self.num_agents = num_agents
        self.agent_basal_cost = agent_basal_cost
        self.production = 0
        self.external_income = 0
        self.expenses = 0
        self.emergency_reserve = 2000

    def apply_scenario(self, scenario_name):
        if scenario_name == "NORMAL":
            self.production += 500
            self.external_income += 200
        elif scenario_name == "PILLAR_LOSS":
            self.pillars["p1_energy"] = 0
            self.amr_reserves -= 1000
        elif scenario_name == "TWO_PILLAR_CRISIS":
            self.pillars["p2_water"] = 0
            self.pillars["p3_agriculture"] = 0
            self.amr_reserves -= 2000
        elif scenario_name == "AGENT_GROWTH":
            self.num_agents *= 2
            self.production *= 1.5
        elif scenario_name == "LOW_EXTERNAL_INCOME":
            self.external_income = 0
        elif scenario_name == "REGENERATIVE_GROWTH":
            self.production += 1000
            self.amr_reserves += 500
            for k in self.pillars:
                self.pillars[k] += 100

    def step(self):
        # Calculate basal costs
        self.expenses = self.num_agents * self.agent_basal_cost
        
        # Net change
        net_change = self.production + self.external_income - self.expenses
        
        if net_change < 0:
            self.amr_reserves += net_change
            if self.amr_reserves < 0:
                self.emergency_reserve += self.amr_reserves
                self.amr_reserves = 0
        else:
            self.amr_circulating += net_change

    def report(self):
        return {
            "pillars_value": sum(self.pillars.values()),
            "amr_reserves": self.amr_reserves,
            "amr_circulating": self.amr_circulating,
            "emergency_reserve": self.emergency_reserve,
            "net_expenses": self.expenses,
            "resilience_status": "STABLE" if self.emergency_reserve > 0 else "CRITICAL"
        }

if __name__ == "__main__":
    sim = AMRSimulator()
    print("Initial State:", json.dumps(sim.report(), indent=2))
    sim.apply_scenario("NORMAL")
    sim.step()
    print("After NORMAL Scenario:", json.dumps(sim.report(), indent=2))
