# pythreatgrid

Python 3 wrapper for the Threat Grid API

## Install

```
git clone https://github.com/Te-k/pythreatgrid.git
cd pythreatgrid
pip install .
```

## Use

Get indicators for all samples connecting to a domain:
```py
from pythreatgrid import ThreatGrid, ThreatGridError

key = ''
tg = ThreatGrid(KEY)
samples = tg.search_samples('google.com', type='domain')
for sample in samples['items']:
    iocs = tg.get_sample_iocs(sample['id'])
```

## Documentation

```
cd docs/build/html
python -m http.server 8000
```

Then visit http://localhost:8000/pythreatgrid.html#module-pythreatgrid
