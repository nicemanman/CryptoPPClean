#pragma once
typedef unsigned char byte;
#include "CryptoPP/filters.h"

using CryptoPP::FilterWithBufferedInput;
using CryptoPP::Filter;

// filters.cpp - originally written and placed in the public domain by Wei Dai

#include "CryptoPP/pch.h"
#include "CryptoPP/config.h"
#include "CryptoPP/filters.h"

#include "CryptoPP/mqueue.h"
#include "CryptoPP/fltrimpl.h"
#include "CryptoPP/argnames.h"
#include "CryptoPP/smartptr.h"
#include "CryptoPP/stdcpp.h"
#include "CryptoPP/misc.h"
#include "../CryptoPP/cryptlib.h"
using CryptoPP::BufferedTransformation;

class GostN : Filter{
	
	size_t Put(const byte* inString, size_t length, bool blocking = true)
	{
		return Put2(inString, length, 0, blocking);
			;
	}

	size_t Put2(const byte* inString, size_t length, int messageEnd, bool blocking)
	{
		return PutMaybeModifiable(const_cast<byte*>(inString), length, messageEnd, blocking, false);
	}

	size_t PutMaybeModifiable(byte* inString, size_t length, int messageEnd, bool blocking, bool modifiable)
{
	if (!blocking)
		throw BufferedTransformation::BlockingInputOnly("FilterWithBufferedInput");

	if (length != 0)
	{
		
		size_t newLength = m_queue.CurrentSize() + length;

		if (!m_firstInputDone && newLength >= m_firstSize)
		{
			size_t len = m_firstSize - m_queue.CurrentSize();
			m_queue.Put(inString, len);
			FirstPut(m_queue.GetContigousBlocks(m_firstSize));
			CRYPTOPP_ASSERT(m_queue.CurrentSize() == 0);
			m_queue.ResetQueue(m_blockSize, (2 * m_blockSize + m_lastSize - 2) / m_blockSize);

			inString = PtrAdd(inString, len);
			newLength -= m_firstSize;
			m_firstInputDone = true;
		}

		if (m_firstInputDone)
		{
			if (m_blockSize == 1)
			{
				while (newLength > m_lastSize&& m_queue.CurrentSize() > 0)
				{
					size_t len = newLength - m_lastSize;
					byte* ptr = m_queue.GetContigousBlocks(len);
					NextPutModifiable(ptr, len);
					newLength -= len;
				}

				if (newLength > m_lastSize)
				{
					size_t len = newLength - m_lastSize;
					NextPutMaybeModifiable(inString, len, modifiable);
					inString = PtrAdd(inString, len);
					newLength -= len;
				}
			}
			else
			{
				while (newLength >= m_blockSize + m_lastSize && m_queue.CurrentSize() >= m_blockSize)
				{
					NextPutModifiable(m_queue.GetBlock(), m_blockSize);
					newLength -= m_blockSize;
				}

				if (newLength >= m_blockSize + m_lastSize && m_queue.CurrentSize() > 0)
				{
					CRYPTOPP_ASSERT(m_queue.CurrentSize() < m_blockSize);
					size_t len = m_blockSize - m_queue.CurrentSize();
					m_queue.Put(inString, len);
					inString = PtrAdd(inString, len);
					NextPutModifiable(m_queue.GetBlock(), m_blockSize);
					newLength -= m_blockSize;
				}

				if (newLength >= m_blockSize + m_lastSize)
				{
					size_t len = RoundDownToMultipleOf(newLength - m_lastSize, m_blockSize);
					NextPutMaybeModifiable(inString, len, modifiable);
					inString = PtrAdd(inString, len);
					newLength -= len;
				}
			}
		}

		m_queue.Put(inString, newLength - m_queue.CurrentSize());
	}

	if (messageEnd)
	{
		if (!m_firstInputDone && m_firstSize == 0)
			FirstPut(NULLPTR);

		SecByteBlock temp(m_queue.CurrentSize());
		m_queue.GetAll(temp);
		LastPut(temp, temp.size());

		m_firstInputDone = false;
		m_queue.ResetQueue(1, m_firstSize);

		// Cast to void to suppress Coverity finding
		(void)Output(1, NULLPTR, 0, messageEnd, blocking);
	}
	return 0;
}
	
};


