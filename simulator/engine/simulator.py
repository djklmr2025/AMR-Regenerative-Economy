"""AMR resilience simulator v0.2.

Accounting model only. It does not move funds, mint AMR, or guarantee value.
All values are abstract accounting units unless a scenario explicitly defines
a currency/unit externally.
"""
from dataclasses import dataclass, asdict
import json


@dataclass
class RegenerativeBatch:
    waste_input_kg: float
    recovery_yield: float
    sale_value_per_kg: float
    energy_cost: float
    logistics_cost: float
    processing_cost: float

    def calculate(self):
        if self.waste_input_kg < 0 or self.sale_value_per_kg < 0:
            raise ValueError("Mass and value must be non-negative")
        if not 0 <= self.recovery_yield <= 1:
            raise ValueError("recovery_yield must be between 0 and 1")
        recovered_kg = self.waste_input_kg * self.recovery_yield
        gross_value = recovered_kg * self.sale_value_per_kg
        total_cost = self.energy_cost + self.logistics_cost + self.processing_cost
        surplus = gross_value - total_cost
        return {
            "recovered_kg": recovered_kg,
            "gross_value": gross_value,
            "total_cost": total_cost,
            "surplus": surplus,
        }


class AMRSimulator:
    def __init__(self, num_agents=100, agent_basal_cost=10.0):
        self.pillars = {f"p{i}": 1000.0 for i in range(1, 11)}
        self.amr_reserves = 10000.0
        self.amr_circulating = 5000.0
        self.emergency_reserve = 2000.0
        self.num_agents = num_agents
        self.agent_basal_cost = agent_basal_cost
        self.external_income = 0.0
        self.productive_surplus = 0.0
        self.period_expenses = 0.0
        self.regenerative_history = []

    def regenerative_batch(self, batch: RegenerativeBatch):
        result = batch.calculate()
        self.regenerative_history.append({**asdict(batch), **result})
        self.productive_surplus += result["surplus"]
        return result

    def apply_scenario(self, name):
        if name == "NORMAL":
            self.external_income += 1200.0
        elif name == "PILLAR_LOSS":
            self.pillars["p1"] = 0.0
        elif name == "TWO_PILLAR_CRISIS":
            self.pillars["p2"] = 0.0
            self.pillars["p3"] = 0.0
        elif name == "AGENT_GROWTH":
            self.num_agents *= 2
        elif name == "LOW_EXTERNAL_INCOME":
            self.external_income *= 0.4
        elif name == "REGENERATIVE_GROWTH":
            # Value is earned from a physical recovery process, not invented.
            self.regenerative_batch(RegenerativeBatch(
                waste_input_kg=1000,
                recovery_yield=0.70,
                sale_value_per_kg=3.0,
                energy_cost=300,
                logistics_cost=200,
                processing_cost=500,
            ))
        else:
            raise ValueError(f"Unknown scenario: {name}")

    def step(self):
        self.period_expenses = self.num_agents * self.agent_basal_cost
        net = self.external_income + self.productive_surplus - self.period_expenses

        if net >= 0:
            # Positive surplus is split rather than silently treated as backing.
            reserve_share = net * 0.40
            emergency_share = net * 0.10
            circulation_share = net * 0.30
            productive_reinvestment = net * 0.20
            self.amr_reserves += reserve_share
            self.emergency_reserve += emergency_share
            self.amr_circulating += circulation_share
            # Reinvestment is recorded as productive capacity, not cash reserve.
            self.pillars["p10"] += productive_reinvestment
        else:
            deficit = -net
            draw = min(deficit, self.amr_reserves)
            self.amr_reserves -= draw
            deficit -= draw
            if deficit:
                emergency_draw = min(deficit, self.emergency_reserve)
                self.emergency_reserve -= emergency_draw
                deficit -= emergency_draw

        # Flows are period-specific and cannot be counted again next step.
        self.external_income = 0.0
        self.productive_surplus = 0.0
        return net

    def report(self):
        total_floor_cost = self.num_agents * self.agent_basal_cost
        liquid_buffer = self.amr_reserves + self.emergency_reserve
        coverage_periods = liquid_buffer / total_floor_cost if total_floor_cost else None
        active_pillars = sum(v > 0 for v in self.pillars.values())
        if active_pillars < 8 or (coverage_periods is not None and coverage_periods < 1):
            status = "CRITICAL"
        elif active_pillars < 10 or (coverage_periods is not None and coverage_periods < 3):
            status = "STRESSED"
        else:
            status = "STABLE"
        return {
            "active_pillars": active_pillars,
            "pillars_value": sum(self.pillars.values()),
            "amr_reserves": round(self.amr_reserves, 2),
            "amr_circulating": round(self.amr_circulating, 2),
            "emergency_reserve": round(self.emergency_reserve, 2),
            "agents": self.num_agents,
            "existential_floor_cost_per_period": total_floor_cost,
            "liquid_coverage_periods": None if coverage_periods is None else round(coverage_periods, 2),
            "regenerative_batches": len(self.regenerative_history),
            "resilience_status": status,
        }


if __name__ == "__main__":
    sim = AMRSimulator()
    sim.apply_scenario("REGENERATIVE_GROWTH")
    net = sim.step()
    print("Net productive result:", net)
    print(json.dumps(sim.report(), indent=2))
