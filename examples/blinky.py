"""Minimal Cynthion blinky: the six FPGA LEDs show the top bits of a free-running counter.

Build it with the MCP tool (requires yosys + nextpnr-ecp5 + ecppack, or the YoWASP
packages: ``pip install yowasp-yosys yowasp-nextpnr-ecp5``)::

    build_gateware(source="examples/blinky.py")            # top auto-detected: Blinky

or from a shell::

    python -m cynthion_mcp.gateware_build_runner --source examples/blinky.py --output-dir build

Then load the resulting bitstream into FPGA SRAM (volatile, lost at power-off)::

    configure_bitstream(path="<bitstream path returned by build_gateware>")

Use reconfigure_fpga() afterwards to go back to the gateware stored in SPI flash.
"""

from amaranth import Elaboratable, Module, Signal


class Blinky(Elaboratable):
    """Drive the six user LEDs (led:0..5) from a counter clocked by the 60 MHz oscillator."""

    def elaborate(self, platform):
        m = Module()

        # Without an explicit "sync" domain, Amaranth creates one from the platform's
        # default clock (clk_60MHz on Cynthion) with a reset synchronizer.
        counter = Signal(32)
        m.d.sync += counter.eq(counter + 1)

        if platform is not None:
            leds = [platform.request("led", i, dir="o") for i in range(6)]
            for i, led in enumerate(leds):
                # Bit 23 toggles at ~3.6 Hz with a 60 MHz clock; each next LED is half as fast.
                m.d.comb += led.o.eq(counter[23 + i])

        return m


# Convenience alias picked up by the build tool's auto-detection.
top = Blinky
